# 【k8s源码阅读】kube-apiserver整体架构&启动流程

> 源码地址：git@github.com:kubernetes/kubernetes.git
> version: 1.21.3
> 不要过于纠结代码的版本，基本架构基本不会发生大的改变。代码细节有所调整。主要目的是要自己走一遍代码流程。
>
> kube-apiserver源码相当复杂，不是一篇文章就能熟悉的。这里先介绍一下kube-apiserver的整体架构以及启动流程。先对一些函数熟悉功能，混个脸熟。

## 一、kube-apiserver架构介绍

kube-apiserver是kubernetes中最核心的组件，各组件之间不会直接通信，而是通过kube-apiserver做中转。
kube-apiserver为丰富周边工具和库生态系统，提供了3种http server服务。主要目的是为了将庞大的kube-apiserver组件功能进行解耦。



其中3种http server分别是：（其中kube-apiserver使用的http框架是一款小众的go-restful框架）

- **APIExtensionsServer**
- **KubeAPIServer**
- **AggregatorServer**

不同的服务的应用场景不同，提供资源不同。但是他们都可以通过kubectl或者接口进行资源管理。

结构设计：





**APIExtensionsServer:**   API扩展服务，提供CRD资源扩展。可以自定义扩展资源，扩展资源由CRD资源对象管理。并通过extensionsapiserver.Scheme资源注册表管理CRD相关资源。
**AggregatorServer: **  API聚合服务，该服务通过AA聚合服务。开发者可通过AA对kubernetes聚合服务进行扩展。例如：metrics-server就是kubernetes集群中核心的监控数据聚合服务。是AggregatorServer的扩展实现。API聚合服务通过APIAggregator对象进行管理，并通过Aggregator对象进行管理，并通过aggregatorscheme.Scheme资源注册表管理AA相关资源。
**KubeAPIServer:** API核心服务，该服务提供kubernetes内置的核心资源，不允许开发者对已经定义的资源进行随意修改。Pod、Service等核心资源由kubernetes官方维护，API核心服务通过Master对象进行管理，并通过legacyscheme.Scheme资源注册表管理相关Master资源。



三种服务都依赖于GenericAPIServer，通过GenericAPIServer将kubernetes资源与REST API进行映射



二、kube-apiserver启动流程
kube-apiserver设计比较复杂，它是所有资源控制的入口。启动流程也是比较复杂的，在整个启动过程中代码逻辑可分为7个步骤：
（1）资源注册
（2）Cobra命令行参数解析
（3）创建APIServer通用配置
（4）创建APIExtensionsServer
（5）创建KubeAPIServer
（6）创建AggregatorServer
（7）启动HTTPS服务

1. 资源注册
   kube-apiserver启动后的第一件事是将Kubernetes支持的所有资源注册到Scheme注册表中。后面启动的逻辑能够直接从Scheme资源注册表中拿到资源信息，并运行APIExtensionsServer、KubeAPIServer、AggregatorServer三种HTTP服务。

kube-apiserver的资源注册是通过go语言的import和init机制触发。
KubeAPIServer核心资源注册到legacyscheme.Scheme
- 初始化资源注册表
  // pkg/api/legacyscheme/scheme.go

```go
var (
// Scheme is the default instance of runtime.Scheme to which types in the Kubernetes API are already registered.
// NOTE: If you are copying this file to start a new api group, STOP! Copy the
// extensions group instead. This Scheme is special and should appear ONLY in
// the api group, unless you really know what you're doing.
// TODO(lavalamp): make the above error impossible.
// 初始化资源注册表
Scheme = runtime.NewScheme()

// Codecs provides access to encoding and decoding for the scheme
// 初始化Codecs，用于编解码
Codecs = serializer.NewCodecFactory(Scheme)

// ParameterCodec handles versioning of objects that are converted to query parameters.
//
ParameterCodec = runtime.NewParameterCodec(Scheme)
)
```

- 注册所支持的资源
  
```go
   package controlplane
   import (
   // These imports are the API groups the API server will support.
   _ "k8s.io/kubernetes/pkg/apis/admission/install"
   _ "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
   _ "k8s.io/kubernetes/pkg/apis/apiserverinternal/install"
   _ "k8s.io/kubernetes/pkg/apis/apps/install"
   _ "k8s.io/kubernetes/pkg/apis/authentication/install"
   _ "k8s.io/kubernetes/pkg/apis/authorization/install"
   _ "k8s.io/kubernetes/pkg/apis/autoscaling/install"
   _ "k8s.io/kubernetes/pkg/apis/batch/install"
   _ "k8s.io/kubernetes/pkg/apis/certificates/install"
   _ "k8s.io/kubernetes/pkg/apis/coordination/install"
   _ "k8s.io/kubernetes/pkg/apis/core/install"
   _ "k8s.io/kubernetes/pkg/apis/discovery/install"
   _ "k8s.io/kubernetes/pkg/apis/events/install"
   _ "k8s.io/kubernetes/pkg/apis/extensions/install"
   _ "k8s.io/kubernetes/pkg/apis/flowcontrol/install"
   _ "k8s.io/kubernetes/pkg/apis/imagepolicy/install"
   _ "k8s.io/kubernetes/pkg/apis/networking/install"
   _ "k8s.io/kubernetes/pkg/apis/node/install"
   _ "k8s.io/kubernetes/pkg/apis/policy/install"
   _ "k8s.io/kubernetes/pkg/apis/rbac/install"
   _ "k8s.io/kubernetes/pkg/apis/scheduling/install"
   _ "k8s.io/kubernetes/pkg/apis/storage/install"
   )
   
   
   func init() {
   Install(legacyscheme.Scheme)
   }

   // Install registers the API group and adds types to a scheme
   func Install(scheme *runtime.Scheme) {
   utilruntime.Must(core.AddToScheme(scheme))
   utilruntime.Must(v1.AddToScheme(scheme))
   utilruntime.Must(scheme.SetVersionPriority(v1.SchemeGroupVersion))
   }
```


2. Cobra命令行参数解析
   cobra是kubernetes系统所有组件统一使用的命令行解析参数库。
   初始化命令行

```go
// NewAPIServerCommand creates a *cobra.Command object with default parameters
func NewAPIServerCommand() *cobra.Command {
s := options.NewServerRunOptions()
cmd := &cobra.Command{
...

RunE: func(cmd *cobra.Command, args []string) error {
verflag.PrintAndExitIfRequested()
fs := cmd.Flags()
cliflag.PrintFlags(fs)

err := checkNonZeroInsecurePort(fs)
if err != nil {
return err
}
// set default options
completedOptions, err := Complete(s)
if err != nil {
return err
}

// validate options
if errs := completedOptions.Validate(); len(errs) != 0 {
return utilerrors.NewAggregate(errs)
}

return Run(completedOptions, genericapiserver.SetupSignalHandler())
}
...
}
```

kube-apiserver组件通过options.NewServerRunOptions()初始化各个模块的默认配置，例如初始化etcd、Audit、admission等模块的默认配置，在通过Complete()函数填充默认的配置参数，并且通过
completedOptions.Validate()做参数的可用性以及合法性做参数校验，最后completedServerRunOptions传入Run()函数。Run函数定义kube-apiserver组件启动的逻辑，它是一个常驻进程。
通过command.Execute()回调

3. 创建APIServer通用配置

```go
   // nodetunneler与node通信，proxy实现代理功能，转发请求给其他apiserver
   // apiserver到cluster的通信可以通过三种方法
   // apiserver到kubelet的endpoint，用于logs功能，exec功能，port-forward功能
   // HTTP连接
   // ssh tunnel
   nodeTunneler, proxyTransport, err := CreateNodeDialer(completedOptions)
   APIServer通用配置是kube-apiserver不同模块是实例化需要的配置
   kubeAPIServerConfig, serviceResolver, pluginInitializer, err := CreateKubeAPIServerConfig(completedOptions, nodeTunneler, proxyTransport)
   if err != nil {
   return nil, err
   }
genericConfig, versionedInformers, serviceResolver, pluginInitializers, admissionPostStartHook, storageFactory, err := buildGenericConfig(s.ServerRunOptions, proxyTransport)
if err != nil {
return nil, nil, nil, err
}
```

（1） genericConfig实例化

```go
genericConfig = genericapiserver.NewConfig(legacyscheme.Codecs)
genericConfig.MergedResourceConfig = controlplane.DefaultAPIResourceConfigSource()
```

这里通过genericapiserver.NewConfig函数实例化genericConfig对象，并且为genericConfig设置默认值。
genericConfig.MergedResourceConfig用于设置启用/禁用GV(资源组、资源版本)以及Resource资源。如果没有在命令行中指定启动/禁用的GV，则通过controlplane.DefaultAPIResourceConfigSource启动默认设置的GV以及资源。并且启动资源版本为Stable和Beta的资源，默认不启用Alpha资源版本的资源。通过EnableVersions函数启动指定资源，而通过DisableVersions函数禁用指定资源

```go
// DefaultAPIResourceConfigSource returns default configuration for an APIResource.
func DefaultAPIResourceConfigSource() *serverstorage.ResourceConfig {
ret := serverstorage.NewResourceConfig()
// NOTE: GroupVersions listed here will be enabled by default. Don't put alpha versions in the list.
ret.EnableVersions(
admissionregistrationv1.SchemeGroupVersion,
admissionregistrationv1beta1.SchemeGroupVersion,
...
)
// enable non-deprecated beta resources in extensions/v1beta1 explicitly so we have a full list of what's possible to serve
ret.EnableResources(
extensionsapiv1beta1.SchemeGroupVersion.WithResource("ingresses"),
)
// disable alpha versions explicitly so we have a full list of what's possible to serve
ret.DisableVersions(
apiserverinternalv1alpha1.SchemeGroupVersion,
nodev1alpha1.SchemeGroupVersion,
rbacv1alpha1.SchemeGroupVersion,
schedulingv1alpha1.SchemeGroupVersion,
storageapiv1alpha1.SchemeGroupVersion,
flowcontrolv1alpha1.SchemeGroupVersion,
)
return ret
}
```

（2）OpenAPI配置
genericConfig.OpenAPIConfig用于生成OpenAPI规范，在默认情况genericapiserver.DefaultOpenAPIConfig函数为其设置默认值
genericConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(generatedopenapi.GetOpenAPIDefinitions, openapinamer.NewDefinitionNamer(legacyscheme.Scheme, extensionsapiserver.Scheme, aggregatorscheme.Scheme))

generatedopenapi.GetOpenAPIDefinitions定义了OpenAPIDefinition文件（由openapi-gen）代码生成器自动生成
（3）StorageFactory存储（Etcd）配置
kube-apiserver组件使用Etcd作为kubernetes系统集群的存储，系统中所有的资源信息，集群状态，配置信息等都存储在Etc中。

```go
storageFactoryConfig := kubeapiserver.NewStorageFactoryConfig()
storageFactoryConfig.APIResourceConfig = genericConfig.MergedResourceConfig
completedStorageFactoryConfig, err := storageFactoryConfig.Complete(s.Etcd)
if err != nil {
lastErr = err
return
}
storageFactory, lastErr = completedStorageFactoryConfig.New()
if lastErr != nil {
return
}
```

kubeapiserver.NewStorageFactoryConfig函数实例化storageFactoryConfig对象，该对象定义了kube-apiserver与Etcd的交互方式。例如Etcd认证、Etcd地址、存储前缀等。该对象也定义了资源存储方式，例如资源信息，资源编码类型，资源状态。
（4）Authentication认证配置
kube-apiserver作为kubernetes集群请求入口，接收组件与客户端的访问请求，每个请求都需要经过认证（Authentication）、授权（Authorization）以及准入控制器（Admission Controller）3个阶段，之后才真正的操作资源。
kube-apiserver目前提供了9种认证机制。分别是BasicAuth、ClientCA、TokenAuth、BootstrapToken、RequestHeader、WebHookTokenAuth、Anonymous、OIDC、ServiceAccountAuth。每一种认证机制被实例化后会成为认证器（Authenticor）。每个认证器都会被封装在http.Handler请求处理函数中，接收组件和客户端代码的请求并认证请求。kube-apiserver通过s.Authentication.ApplyTo函数实例化认证器。

```go
// Authentication.ApplyTo requires already applied OpenAPIConfig and EgressSelector if present
if lastErr = s.Authentication.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.EgressSelector, genericConfig.OpenAPIConfig, clientgoExternalClient, versionedInformers); lastErr != nil {
return
}
```

（5）Authorization配置
在kube-apiserver系统组件或者客户端请求通过认证阶段之后，会到授权阶段。kube-apiserver同样支持多种授权机制，并支持同时开启多个授权功能，客户端发起一个请求，在经过授权阶段时，只有一个授权器能够授权成功。
kube-apiserver目前提供了6种授权机制，分别是AlwaysAllow、AlwaysDeny、WebHook、Node、ABAC、RBAC。每一种授权机制被实例化之后会成为授权器（Authorizer），每一种授权器都等装在http-apiservert通过BuildAuthorizer授权器

```go
genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, err = BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)
if err != nil {
lastErr = fmt.Errorf("invalid authorization config: %v", err)
return
}
```

(6) Admission准入控制配置
kube-apiserver系统组件或者客户端在通过授权阶段之后，会进入到准入控制阶段，会在认证授权之后，对象被持久化之前，拦截kube-apiserver的请求。拦截后的请求进入准入控制器中处理，对请求的资源对象进行自定义（校验，修改或者拒绝）等操作。kube-apiserver支持多种准入控制器，并支持同时开启多个准入控制的功能。如果开启多个准入控制器，则需要按照顺序执行准入控制器。

```go
err = s.Admission.ApplyTo(
genericConfig,
versionedInformers,
kubeClientConfig,
feature.DefaultFeatureGate,
pluginInitializers...)
if err != nil {
lastErr = fmt.Errorf("failed to initialize admission: %v", err)
}
```

默认支持的准入控制器：

```go
// RegisterAllAdmissionPlugins registers all admission plugins and
// sets the recommended plugins order.
func RegisterAllAdmissionPlugins(plugins *admission.Plugins) {
admit.Register(plugins) // DEPRECATED as no real meaning
alwayspullimages.Register(plugins)
antiaffinity.Register(plugins)
defaulttolerationseconds.Register(plugins)
defaultingressclass.Register(plugins)
denyserviceexternalips.Register(plugins)
deny.Register(plugins) // DEPRECATED as no real meaning
eventratelimit.Register(plugins)
extendedresourcetoleration.Register(plugins)
gc.Register(plugins)
imagepolicy.Register(plugins)
limitranger.Register(plugins)
autoprovision.Register(plugins)
exists.Register(plugins)
noderestriction.Register(plugins)
nodetaint.Register(plugins)
label.Register(plugins) // DEPRECATED, future PVs should not rely on labels for zone topology
podnodeselector.Register(plugins)
podtolerationrestriction.Register(plugins)
runtimeclass.Register(plugins)
resourcequota.Register(plugins)
podsecuritypolicy.Register(plugins)
podpriority.Register(plugins)
scdeny.Register(plugins)
serviceaccount.Register(plugins)
setdefault.Register(plugins)
resize.Register(plugins)
storageobjectinuseprotection.Register(plugins)
certapproval.Register(plugins)
certsigning.Register(plugins)
certsubjectrestriction.Register(plugins)
}
```



4. 创建APIExtensionsServer
   返回CreateServerChain：

```go
// If additional API servers are added, they should be gated.
apiExtensionsConfig, err := createAPIExtensionsConfig(*kubeAPIServerConfig.GenericConfig, kubeAPIServerConfig.ExtraConfig.VersionedInformers, pluginInitializer, completedOptions.ServerRunOptions, completedOptions.MasterCount,
serviceResolver, webhook.NewDefaultAuthenticationInfoResolverWrapper(proxyTransport, kubeAPIServerConfig.GenericConfig.EgressSelector, kubeAPIServerConfig.GenericConfig.LoopbackClientConfig))
if err != nil {
return nil, err
}
apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
if err != nil {
return nil, err
}
```

kube-apiserver在完成通用的配置初始化之后，进行三大Http服务的创建。首先创建apiExtensionsServer。
（1）创建genericServer

```go
genericServer, err := c.GenericConfig.New("apiextensions-apiserver", delegationTarget)
if err != nil {
return nil, err
}
```

（2）实例化CustomResourceDefinitions

```go
s := &CustomResourceDefinitions{
GenericAPIServer: genericServer,
}
```

APIExtensionsServer(API扩展服务)通过CustomResourceDefinitions对象进行管理，实例化这个对象之后，才能注册APIExtensionsServer下的资源
（3）实例化APIGroupInfo, 将资源版本，资源，资源存储对象进行相互映射。
用于描述资源组信息

```go 
apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(apiextensions.GroupName, Scheme, metav1.ParameterCodec, Codecs)
```

（4）InstallAPIGroup注册APIGroup(apiextensions.k8s.io)

```go
if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
return nil, err
}
```

InstallAPIGroup注册APIGroupInfo的过程，将APIGroupInfo对象中的<资源组>/<资源版本>/<资源>/<子资源>（包括资源存储对象）注册到APIExtensionsServerHandler函数。

```go
s.DiscoveryGroupManager.AddGroup(apiGroup)
s.Handler.GoRestfulContainer.Add(discovery.NewAPIGroupHandler(s.Serializer, apiGroup).WebService())
```

5. 创建KubeAPIServer
   创建KubeAPIServer的流程与创建APIExtensionsServer的流程类似，其原理都是将<资源组>/<资源版本>/<资源>与资源对象进行映射，并将其存到APIGroupInfo对象。
   通过installer.Install安装器为资源注册对应的Handlers方法（即资源存储对象Resource Storage）,完成资源与Handles方法绑定并在go-restflu WebService添加该路由。最后将WebService添加到go-restful Container。
   创建KubeAPIServer流程：
   （1）实例化GenericAPIServer

```go
s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
if err != nil {
return nil, err
}
```

KubeAPIServer的运行依赖于 GenericAPIServer，通过c.GenericConfig.New函数创建一个名为kube-apiserver的服务。
(2)   实例化Instance

```go
m := &Instance{
GenericAPIServer:          s,
ClusterAuthenticationInfo: c.ExtraConfig.ClusterAuthenticationInfo,
}
```

KubeAPIServer通过实例化Instance对象进行管理，实例化该对象之后才能注册KubeAPIServer下的资源。
(3) InstallegacyAPI注册/api资源

```go
// install legacy rest storage
if c.ExtraConfig.APIResourceConfigSource.VersionEnabled(apiv1.SchemeGroupVersion) {
legacyRESTStorageProvider := corerest.LegacyRESTStorageProvider{
StorageFactory:              c.ExtraConfig.StorageFactory,
ProxyTransport:              c.ExtraConfig.ProxyTransport,
...
}
if err := m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter, legacyRESTStorageProvider); err != nil {
return nil, err
}
}
```

KubeAPIServer会先判断Core Groups/v1(即核心资源组和资源版本是否已启用)，如果已经启用，则通过m.InstallLegacyAPI将Core Groups/v1注册到KubeAPIServer的/api/v1下。可以通过访问curl ip:port/api/v1获取core资源与子资源。
(4) InstallAPIs注册/apis资源

```go
restStorageProviders := []RESTStorageProvider{
apiserverinternalrest.StorageProvider{},
...
// keep apps after extensions so legacy clients resolve the extensions versions of shared resource names.
// See https://github.com/kubernetes/kubernetes/issues/42392
appsrest.StorageProvider{},
admissionregistrationrest.RESTStorageProvider{},
eventsrest.RESTStorageProvider{TTL: c.ExtraConfig.EventTTL},
}
if err := m.InstallAPIs(c.ExtraConfig.APIResourceConfigSource, c.GenericConfig.RESTOptionsGetter, restStorageProviders...); err != nil {
return nil, err
}
```


6. 创建AggregatorServer
   流程上同，不在分析
   AggregatorServer的创建流程与APIExtensionsServer流程类似。
   （1）实例化GenericAPIServer
   （2）实例化APIAggregator
     (3)   实例化APIGroupInfo
     (4)  installAPIGroup注册APIGroup(apiregistration.k8s.io)
7. 启动HTTPS服务
   go语言本身有功能丰富的HTTP标准库，kube-apiserver在其基础上并没有做过多的封装。通过http.ListenAndServer函数启动HTTP服务。内部实现创建Socket、监控端口等操作。
   https在http基础上增加了传输层协议TLS

```go
// Run spawns the secure http server. It only returns if stopCh is closed
// or the secure port cannot be listened on initially.
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
delayedStopCh := make(chan struct{})
...
// close socket after delayed stopCh
stoppedCh, err := s.NonBlockingRun(delayedStopCh)
...
}

// Serve runs the secure http server. It fails only if certificates cannot be loaded or the initial listen call fails.
// The actual server loop (stoppable by closing stopCh) runs in a go routine, i.e. Serve does not block.
// It returns a stoppedCh that is closed when all non-hijacked active requests have been processed.
func (s *SecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, error) {
if s.Listener == nil {
return nil, fmt.Errorf("listener must not be nil")
}

tlsConfig, err := s.tlsConfig(stopCh)
if err != nil {
return nil, err
}

secureServer := &http.Server{
Addr:           s.Listener.Addr().String(),
Handler:        handler,
MaxHeaderBytes: 1 << 20,
TLSConfig:      tlsConfig,
}
...  
}

// 优雅关闭
// Shutdown server gracefully.
stoppedCh := make(chan struct{})
go func() {
defer close(stoppedCh)
<-stopCh
ctx, cancel := context.WithTimeout(context.Background(), shutDownTimeout)
server.Shutdown(ctx)
cancel()
}()
```





