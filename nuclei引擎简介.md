
Nuclei 源码分析


# 1. nuclei简介
Nuclei 是一款基于模板的漏洞扫描工具，诞生于 2020 年 4 月左右。

市面上多数的开源或商业的漏洞扫描器都是脚本/插件形式开发的，而Nuclei 主打“模板”的概念，所有的检测规则并非是传统的 API 方式开发的脚本，而是 YAML 格式的纯文本；长亭的 xray 也采用了类似的方式提供检测插件。

更高的抽象维度来看，开发大多漏洞检测插件其实都是在做同一个模式的重复事情：构造 PoC -> 发包 -> 检测响应结果；遵循这个规律其实完全可以把流程抽象出来；所以我觉得基于模板的插件是非常好的一个选择，可以更专注漏洞本身，也能更高效地完成检测插件。

回到 Nuclei，它基于 Go 语言开发，得益于 Go 语言天然优势，Nuclei 天生具备：

可编译为单文件的二进制格式，解决了依赖问题，便于升级；
跨平台；
并发能力强。

我用 cloc 统计了下 Nuclei 代码量，go代码约3w+，细节统计如下：
github.com/AlDanial/cloc v 1.92  T=3.11 s (124.2 files/s, 16019.0 lines/s)

|   Language   | files | blank | comment | code  |
|:------------:|:-----:|:-----:|:-------:|:-----:|
|      Go      |  290  | 4756  |  2896   | 32280 |
|   Markdown   |  16   | 2508  |    0    | 3909  |
|     YAML     |  68   |  202  |   140   | 1325  |
|     JSON     |   1   |   0   |    0    | 1305  |
|     SQL      |   1   |  46   |   37    |  193  |
|     XML      |   3   |   0   |    0    |  50   |
|     Java     |   2   |   6   |    0    |  39   |
| Bourne Shell |   2   |   7   |    1    |  36   |
|     make     |   1   |   1   |    1    |  24   |
|  Dockerfile  |   2   |   2   |    0    |  16   |
|     SUM      |  386  | 7528  |  3075   | 39177 |

通常我们说的漏洞扫描工具，指的是包含了爬虫、通用漏洞检测（如 SQL 注入、XSS 检测）、指纹信息收集（如 Web 服务、语言框架等）、专用漏洞检测；Nuclei 只是其中完成“检测”这部分工作，同时官方是把检测引擎和“模板”分开维护的：

引擎代码：https://github.com/projectdiscovery/nuclei/。
模板：https://github.com/projectdiscovery/nuclei-templates， 平均 3 天发布一个版本。
模板编写参考官方给的指南：https://nuclei.projectdiscovery.io/templating-guide/index.html， Nuclei 模板目前(我们二开当前所用版本)支持以下协议：

- DNSProtocol
- FileProtocol
- HTTPProtocol
- HeadlessProtocol
- NetworkProtocol
- WorkflowProtocol
- SSLProtocol
- WebsocketProtocol
- WHOISProtocol

nuclei可抽象分为模板引擎、执行引擎和报告引擎三大块核心功能区：

- 模板引擎：前期负责模板的导入转换和规则检查，中期负责发出具体规则载荷，后期利用匹配器进行响应检查，接受执行引擎的调度；
- 执行引擎：接收模板引擎输入的可执行POC规则和目标，并由一个执行配置项来调配运行时期间的各类参数，包括一系列模板和速率以及协程数限制等；
- 报告引擎：报告引擎根据配置定义来输出对应的报告格式，nuclei支持多种报告格式的输出，包括：markDown、sarif、elasticsearch；

> 商用情况下的一些考虑:值得一提的是，Nuclei 使用了 MIT 开源协议，MIT 是一种非常宽松的许可协议，修改源码后商用且闭源，唯一限制是必须保留原有版权信息，所以 Nuclei 是能直接商用的。

## Nuclei 还有一些欠缺的地方：

- 不支持加密的 YAML，YAML 通常属于商业竞争能力需要得到一定的保护。
- 框架不具备对插件测试功能，不能通过 CI 等自动化方式来保证 YAML 的质量。
- Nuclei 通过 Github 方式更新检测规则，而不支持指定规则更新服务器。
- 自身无持久化方案，模板读取基于磁盘文件。

# 2. 模板引擎

nuclei的模板引擎是整个业务流程的核心部分，负责规则的编制检查，存储转换，载荷执行和响应检查等一系列具体操作。由执行引擎统一调度，放入指定协程内并发执行。
nuclei模板由一个公共属性Info和各协议自身实现细节组成，其中Info包含了模板的各类元信息，结构如下：

```
type Info struct {
	Name string 
	Authors stringslice.StringSlice 
	Tags stringslice.StringSlice
	Description string 
	Reference stringslice.StringSlice 
	SeverityHolder severity.Holder
	Metadata map[string]interface{} 
	Classification *Classification
	Remediation string 
}
```

其中主要介绍Tags和Metadata两个属性：Tags是一组自定义标签，用以标识模板的属性，主要用于在执行加载前进行分类筛选和过滤；
Metadata是一个自定义元信息MAP，主要针对模板信息的元数据进行信息字段扩展，可填入自定义的元信息键值对。

## 模板接口规范

在第一部分介绍了nuclei目前已支持的协议模板类型，所有协议都遵循nuclei内置的一组接口规范，了解该接口规范有助于后期对支持协议进行扩展改进。
接口规范定义在nuclei/v2/pkg/protocols/protocols.go，细节如下：

```
// 任何基于nuclei的执行器调度的模板协议均需实现以下方法：
type Request interface {
	// 模板自编译：编译请求生成器，对发出的请求进行预处理
	Compile(options *ExecuterOptions) error
	// 返回该模板的请求总数
	Requests() int
	// 返回模板ID
	GetID() string
	// 匹配操作，入参为请求发出后的响应体，和对应的匹配器，需返回是否命中及命中片段(如果有的话)
	Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
	//提取操作，输入响应体和提取器，返回提取结果
	//ps:这里提取器的入参名matcher应该是他源码里的手误。。。应该用extractor，他源码里http协议在实现的时候就纠正了这个，虽然没啥影响，但是命名会产生严重歧义
	Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	// 执行模板并写入结果，这是该模板的最终执行逻辑，通过callback将执行过程中需要反馈的数据输出至报告引擎
	// OutputEventCallback是一个函数定义，用于在模板执行生命周期内将各类数据输出至报告引擎，后文详解
	ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
	// 返回请求的执行结果，填充output.ResultEvent结构体后返回即可
	MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
	// 内部事件的封装，这里均由内置的MakeDefaultResultEvent函数去实现了，目前无需关心
	MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
	// 返回Compile方法生成的所有请求操作器，具体结构参考operators.Operators，里面主要包含请求的匹配器和提取器以及他们的与或条件
	GetCompiledOperators() []*operators.Operators
	// 返回模板的类型，新增自定义协议的模板前提需在templates.types.types内添加自定义协议的名称信息
	Type() templateTypes.ProtocolType
}
```

在理解以上接口规范所定义的方法后，可通过实现上述接口的形式来方便的扩展nuclei支持的协议类型，其中Compile方法实现细节较为复杂。

## 匹配器介绍

在整个poc执行过程中，是否命中由模板中的匹配器来进行识别判断，当前匹配器支持status、size、word、regex、binary和dsl六种模式。
匹配器可以由多个不同模式的条件组成，条件之前的与或关系也可自由定义，这些细节在官方模板介绍文档中均有介绍，这里主要介绍以下DSL自定义内置函数模式。

dsl的定义位于nuclei/v2/pkg/operators/common/dsl/dsl.go文件，通过源码可以看到dsl的结构很简单，只有一个signature签名和一个expressFunc函数定义。
dsl的目的是在编写自定义yaml格式的poc模板时，通过自定义函数的形式为编写者提供更多方便实用的功能，而这些功能通过模板自编译转换后，由golang进行实际处理。

我们来看一个简单的dsl自定义函数 `to_upper` 的具体实现：

```
"to_upper": makeDslFunction(1, func(args ...interface{}) (interface{}, error) {
			return strings.ToUpper(types.ToString(args[0])), nil
		})
```

其中`makeDslFunction`是nuclei的内置加工函数，可以先忽略，“to_upper”表明的自定义内置函数名，
在编写poc时就可以在dsl的匹配器内用`to_upper(...)`形式来调用，而该函数实际的实现则是在匹配器提取出dsl模式后，进入dsl自定义函数池，找出“to_upper”
对应的函数体`return strings.ToUpper(types.ToString(args[0])), nil`，由golang实现将入参转换为大写字符串，由于函数体内`args[0]`表明
该自定义dsl只接收一个入参，因此在编写poc调用时应该只传入一个参数`to_upper(param)`。

nuclei在源码内贴心的准备了`func AddHelperFunction(key string, value func(args ...interface{}) (interface{}, error)) error`
这是添加自定义dsl函数的函数(有点绕口哈哈)，方便我们后续为编写poc添加更多自定义dsl辅助函数。

## 提取器介绍

提取器Extractor作用在于提取响应体中的内容用于后续请求，如登录后提取token，并用token进行授权请求等场景。提取器目前支持4种类型：

- RegexExtractor: "regex"
- KValExtractor:  "kval"
- XPathExtractor: "xpath"
- JSONExtractor:  "json"

四种类型由各自独立的实现方式，相对都比较简单，这里就不做过多介绍了，有兴趣的同学可以直接查看源码`nuclei/v2/pkg/operators/extractors/extract.go`

# 3. 执行引擎

nuclei的所有模板均由执行引擎统一调度执行，执行引擎结构如下：

```
type Engine struct {
	workPool     *WorkPool
	options      *types.Options
	executerOpts protocols.ExecuterOptions
}
```

虽然这里看着只有三个属性，但是其中除workPool以外，另外两个options和executerOpts属性都非常多，且其核心的执行方法`ExecuteWithOpts(ctx context.Context, templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool` 其过程也较为复杂。
下面逐个介绍一下他的三个属性以及核心执行方法的概要。

## workPool

workPool是nuclei引擎运行时的协程池，可以为不同的类型启用不同数量协程的协程池，其结构也较为简单：

```
type WorkPool struct {
	Headless *sizedwaitgroup.SizedWaitGroup
	Default  *sizedwaitgroup.SizedWaitGroup
	config   WorkPoolConfig
}
```

其中config主要是定义headLess和缺省类型的协程池内的协程数量，而sizedwaitgroup.SizedWaitGroup则是一个第三方库，是对golang内置waitGroup的一个封装，用以控制并发协程数量。
很老的一个库，后期可以考虑更新使用ants协程池替换。

## options

options包含了引擎中的poc规则过滤选项，如tags，排除列表，作者，严重等级一系列过滤条件；除了是一个过滤器外，options还包含了请求速率、并行协程数和超时时间重试次数等常规配置项。
options虽然字段较多，但均为常规配置项，不难理解，nuclei使用的缺省options如下：

```
// DefaultOptions returns default options for nuclei
func DefaultOptions() *Options {
	return &Options{
		RateLimit:               150,   //速率限制
		BulkSize:                25,   //多目标下并发访问目标数
		TemplateThreads:         25,   //模板执行时的并发数
		HeadlessBulkSize:        10,   //Headless多目标下并发访问目标数
		HeadlessTemplateThreads: 10,   //Headless模板执行时的并发数
		Timeout:                 5,    //单个响应超时时间，单位秒
		Retries:                 1,    //单个请求重试次数
		MaxHostError:            30,   //单个目标最大允许错误数
	}
}
```

## executerOpts

executerOpts与options的主要区别在于：options是用于引擎的全局配置项和加载poc模板时的过滤器；而executerOpts是在执行引擎执行每个模板时，
针对单个模板，根据模板的差异提供个性化选项，最核心的部分在于executerOpts提供了与报告引擎的关联输出。
executerOpts中的Output在模板执行时，向报告引擎输出各类事件。

## ExecuteWithOpts

执行引擎在创建时，通过接收模板引擎传入的数据构造options，对poc模板进行过滤后加载成`finalTemplates`最终待执行模板列表。
通过workPool创建协程池后，将`finalTemplates`列表中的待执行模板取出放入执行队列，调用其内置的执行方法`executeModelWithInput(ctx context.Context, templateType types.ProtocolType, template *templates.Template, target InputProvider, results *atomic.Bool) `
对poc模板中的具体请求执行并向报告模板关联的Output写入各种相关事件。

由于函数体过大，下面摘出其中关键一小部分：

```
err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent) {
			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					previous[builder.String()] = v
					builder.Reset()
				}
			}
			// If no results were found, and also interactsh is not being used
			// in that case we can skip it, otherwise we've to show failure in
			// case of matcher-status flag.
			if event.OperatorsResult == nil && !event.UsesInteractsh {
				if err := e.options.Output.WriteFailure(event.InternalEvent); err != nil {
					gologger.Warning().Msgf("Could not write failure event to output: %s\n", err)
				}
			} else {
				if writer.WriteResult(event, e.options.Output, e.options.Progress, e.options.IssuesClient) {
					results = true
				}
			}
		})
```

整体执行逻辑其实是由poc模板自己所属协议的结构体进行，并不是由执行引擎发出，执行引擎只负责调度执行，实际发出请求还是由模板自身，参考上述源码第一行：
`err := req.ExecuteWithResults(input, dynamicValues, previous, func(event *output.InternalWrappedEvent)`,
这个方法就是第二章模板协议规范中的执行方法，为了更了解其工作流程，我们参考nuclei内置的http协议中该方法的具体实现：

```
err = request.executeRequest(reqURL, generatedHttpRequest, previous, hasInteractMatchers, func(event *output.InternalWrappedEvent) {
				// Add the extracts to the dynamic values if any.
				if event.OperatorsResult != nil {
					gotMatches = event.OperatorsResult.Matched
					gotDynamicValues = generators.MergeMapsMany(event.OperatorsResult.DynamicValues, dynamicValues, gotDynamicValues)
				}
				if hasInteractMarkers && hasInteractMatchers && request.options.Interactsh != nil {
					request.options.Interactsh.RequestEvent(generatedHttpRequest.interactshURLs, &interactsh.RequestData{
						MakeResultFunc: request.MakeResultEvent,
						Event:          event,
						Operators:      request.CompiledOperators,
						MatchFunc:      request.Match,
						ExtractFunc:    request.Extract,
					})
				} else {
					callback(event)
				}
			}, requestCount)
```

上面虽然篇幅较大，但其实第一行只是调用其内置的executeRequest方法去执行请求，而func(event *output.InternalWrappedEvent)...后面只是传入了一个与报告引擎相关联的处理函数。
而request.executeRequest方法由于篇幅更大就不贴了，基本思路就是根据poc规则的载荷生成请求体，调用http客户端对目标发送指定请求后，
对响应体使用匹配器和提取器进行处理，同时向报告引擎输出执行相关数据。

执行引擎在处理请求时，将执行细节和方法都交由模板协议自身去实现，自己只负责统筹调度，因此在后期扩展和优化时，应考虑在编写模板协议时加大投入。

# 4. 报告引擎

报告引擎负责对nuclei执行过程和结果的记录以及输出，它在nuclei执行引擎创建时加入到其executerOpts属性中的Output项。
Output是nuclei对执行输出的一个接口规范，其内容如下：

```
// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	// 关闭方法用来在执行结束后释放报告引擎持有的各类资源，如fd或数据库连接等
	Close()
	// 颜色渲染，一般用于命令行stdOut
	Colorizer() aurora.Aurora
	// 核心的结果接入方法，入参为模板的执行结果，实现者可自行将结果输出至自定义的地方如文件或数据库，屏幕输出等
	Write(*ResultEvent) error
	// 执行失败的接入方法，入参为失败事件
	WriteFailure(event InternalEvent) error
	// 执行请求时的相关信息，模板id，请求类型以及错误
	Request(templateID, url, requestType string, err error)
}
```

只要实现以上接口规范定义的方法，再替换掉执行引擎executerOpts属性中的Output，就可以实现自定义nuclei的报告输出。
下面看一下nuclei自身的标准实现，主要关注：`Write(*ResultEvent) error`和`WriteFailure(event InternalEvent) error`两个方法的实现

- Write(*ResultEvent) error

```
// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event *ResultEvent) error {
	// Enrich the result event with extra metadata on the template-path and url.
	if event.TemplatePath != "" {
		event.Template, event.TemplateURL = utils.TemplatePathURL(types.ToString(event.TemplatePath))
	}
	event.Timestamp = time.Now()

	var data []byte
	var err error

	if w.json {                // 这里如果实现者定义用json格式输出，则将事件序列化成json
		data, err = w.formatJSON(event)
	} else {                // 否则按标准日志格式输出
		data = w.formatScreen(event)
	}
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	if len(data) == 0 {
		return nil
	}
	_, _ = os.Stdout.Write(data)     // 将数据写入屏幕输出
	_, _ = os.Stdout.Write([]byte("\n"))
	if w.outputFile != nil {           // 如果定义了输出文件，则将信息输出至文件
		if !w.json {
			data = decolorizerRegex.ReplaceAll(data, []byte(""))
		}
		if _, writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}  
```

- WriteFailure(event InternalEvent) error

```
// WriteFailure writes the failure event for template to file and/or screen.
func (w *StandardWriter) WriteFailure(event InternalEvent) error {
	if !w.matcherStatus {
		return nil
	}
	templatePath, templateURL := utils.TemplatePathURL(types.ToString(event["template-path"]))
	data := &ResultEvent{      //这里nuclei的实现是把错误封装成一个事件，调用Write方法，将错误当作一个事件写入
		Template:      templatePath,
		TemplateURL:   templateURL,
		TemplateID:    types.ToString(event["template-id"]),
		TemplatePath:  types.ToString(event["template-path"]),
		Info:          event["template-info"].(model.Info),
		Type:          types.ToString(event["type"]),
		Host:          types.ToString(event["host"]),
		MatcherStatus: false,
		Timestamp:     time.Now(),
	}
	return w.Write(data)
}
```

由于nuclei并没有提供持久化，因此如果要外接数据源，则需自己实现Writer接口规范，比如将事件写入数据库，则可在Write(*ResultEvent) error方法内调用数据库驱动，
优雅的将ResultEvent写入数据库。