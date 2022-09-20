## 【k8s源码阅读】kube-apiserver bootstrap-controller

> kube-apiserver作为一个web server。需要对外提供访问方式。集群外部可以直接访问kube-apiserver地址进行访问。集群内部提供了一种云原生的访问模式。即 pod 中可以通过访问 service 为 kubernetes 的 ClusterIP，kubernetes 集群在初始化完成后就会创建一个 kubernetes service，该 service 是 kube-apiserver 创建并进行维护的。

```shell
 shuaiwang@shuaideMacBook-Pro  ~  kubectl get svc  kubernetes
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.233.0.1   <none>        443/TCP   400d
 shuaiwang@shuaideMacBook-Pro  ~  kubectl get endpoints  kubernetes
NAME         ENDPOINTS                              AGE
kubernetes   10.38.201.158:6443,10.38.201.65:6443   400d
```

kubernetes service 是由 kube-apiserver 中的 bootstrap-controller 进行控制的，其主要以下几个功能：

- 创建 kubernetes service；

- 创建 default, kube-system 和 kube-public 以及 kube-node-lease 命名空间；

- 提供基于 Service ClusterIP 的修复及检查功能；

- 提供基于 Service NodePort 的修复及检查功能；

kubernetes service 默认使用 ClusterIP 对外暴露服务，若要使用 NodePort 的方式可在 kube-apiserver 启动时通过 `--kubernetes-service-node-port` 参数指定对应的端口

## 代码：

### 初始化和启动：

代码路径：pkg/controlplane/instance.go

bootstrap controller 的初始化以及启动是在 `CreateKubeAPIServer` 调用链的 `InstallLegacyAPI` 方法中完成的，bootstrap controller 的启停是由 apiserver 的 `PostStartHook` 和 `PreShutdownHook` 进行控制的（调用链省略了）

```Go
// InstallLegacyAPI will install the legacy APIs for the restStorageProviders if they are enabled.
func (m *Instance) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter, legacyRESTStorageProvider corerest.LegacyRESTStorageProvider) error {
   legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(restOptionsGetter)
   if err != nil {
      return fmt.Errorf("error building core storage: %v", err)
   }
   controllerName := "bootstrap-controller"
   coreClient := corev1client.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
   bootstrapController := c.NewBootstrapController(legacyRESTStorage, coreClient, coreClient, coreClient, coreClient.RESTClient())
   m.GenericAPIServer.AddPostStartHookOrDie(controllerName, bootstrapController.PostStartHook)
   m.GenericAPIServer.AddPreShutdownHookOrDie(controllerName, bootstrapController.PreShutdownHook)

   if err := m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo); err != nil {
      return fmt.Errorf("error in registering group versions: %v", err)
   }
   return nil
}
```

**启动：**

```Go
// Run spawns the secure http server. It only returns if stopCh is closed
// or the secure port cannot be listened on initially.
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
    ...
   // close socket after delayed stopCh
   // 启动前运行hooks
   stoppedCh, err := s.NonBlockingRun(delayedStopCh)
   if err != nil {
      return err
   }
   <-stopCh
   // run shutdown hooks directly. This includes deregistering from the kubernetes endpoint in case of kube-apiserver.
   // 退出前 运行Shutdown hooks
   err = s.RunPreShutdownHooks()
   if err != nil {
      return err
   }
   ...
   return nil
}
```

### bootstrap controller

代码路径：pkg/controlplane/controller.go

```Go
// NewBootstrapController returns a controller for watching the core capabilities of the master
func (c *completedConfig) NewBootstrapController(legacyRESTStorage corerest.LegacyRESTStorage, serviceClient corev1client.ServicesGetter, nsClient corev1client.NamespacesGetter, eventClient corev1client.EventsGetter, readyzClient rest.Interface) *Controller {
  // 获取apiserver 安全端口
   _, publicServicePort, err := c.GenericConfig.SecureServing.HostPort()
   if err != nil {
      klog.Fatalf("failed to get listener address: %v", err)
   }
   // 系统ns, kube-system 和 kube-public 以及 kube-node-lease
   systemNamespaces := []string{metav1.NamespaceSystem, metav1.NamespacePublic, corev1.NamespaceNodeLease}
   return &Controller{
      // 各种资源客户端
      ServiceClient:   serviceClient,
      NamespaceClient: nsClient,
      EventClient:     eventClient,
      readyzClient:    readyzClient,
     
      EndpointReconciler: c.ExtraConfig.EndpointReconcilerConfig.Reconciler,
      EndpointInterval:   c.ExtraConfig.EndpointReconcilerConfig.Interval,
      SystemNamespaces:         systemNamespaces,
      SystemNamespacesInterval: 1 * time.Minute,
      ServiceClusterIPRegistry:          legacyRESTStorage.ServiceClusterIPAllocator,
      // --service-cluster-ip-range 参数指定  
      ServiceClusterIPRange:             c.ExtraConfig.ServiceIPRange,
      // 取 clusterIP range 中的第一个 IP    
      ServiceIP:                 c.ExtraConfig.APIServerServiceIP,
      // 默认为 443    
      ServicePort:               c.ExtraConfig.APIServerServicePort,
      ExtraServicePorts:         c.ExtraConfig.ExtraServicePorts,
      ExtraEndpointPorts:        c.ExtraConfig.ExtraEndpointPorts,
      // 通过--secure-port指定，默认为6443
      PublicServicePort:         publicServicePort,
      KubernetesServiceNodePort: c.ExtraConfig.KubernetesServiceNodePort,
   }
}
```

### start:

```Swift
// Start begins the core controller loops that must exist for bootstrapping
// a cluster.
func (c *Controller) Start() {
   if c.runner != nil {
      return
   }
   // Reconcile during first run removing itself until server is ready.
   endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
   if err := c.EndpointReconciler.RemoveEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts); err != nil {
      klog.Errorf("Unable to remove old endpoints from kubernetes service: %v", err)
   }
   repairClusterIPs := servicecontroller.NewRepair(c.ServiceClusterIPInterval, c.ServiceClient, c.EventClient, &c.ServiceClusterIPRange, c.ServiceClusterIPRegistry, &c.SecondaryServiceClusterIPRange, c.SecondaryServiceClusterIPRegistry)
   repairNodePorts := portallocatorcontroller.NewRepair(c.ServiceNodePortInterval, c.ServiceClient, c.EventClient, c.ServiceNodePortRange, c.ServiceNodePortRegistry)
   // run all of the controllers once prior to returning from Start.
   if err := repairClusterIPs.RunOnce(); err != nil {
      // If we fail to repair cluster IPs apiserver is useless. We should restart and retry.
      klog.Fatalf("Unable to perform initial IP allocation check: %v", err)
   }
   if err := repairNodePorts.RunOnce(); err != nil {
      // If we fail to repair node ports apiserver is useless. We should restart and retry.
      klog.Fatalf("Unable to perform initial service nodePort check: %v", err)
   }

   c.runner = async.NewRunner(c.RunKubernetesNamespaces, c.RunKubernetesService, repairClusterIPs.RunUntil, repairNodePorts.RunUntil)
   c.runner.Start()
}
```

上文提到过kube-apiserver会运行起来前调用BootstrapController.PostStartHook，该函数涵盖了bootstrapController的核心功能，主要包括：修复 ClusterIP、修复 NodePort、更新 kubernetes service以及创建系统所需要的名字空间（default、kube-system、kube-public）。bootstrap controller 在启动后首先会完成一次 ClusterIP、NodePort 和 Kubernets 服务的处理，然后异步循环运行上面的4个工作。

- 首次启动时首先从 kubernetes endpoints 中移除自身的配置，此时 kube-apiserver 可能处于非 ready 状态, 重新从etcd中获取master ip创建endpoints

```CSS
RemoveEndpoints
--> r.masterLeases.RemoveLease(ip.String())
--> r.doReconcile
    --> r.epAdapter.Create(corev1.NamespaceDefault, e) OR Update
```

- 初始化 repairClusterIPs 和 repairNodePorts 对象  

```CSS
// 创建控制器确保整个集群的ClusterIP能被唯一分配
servicecontroller.NewRepair
// 创建控制器确保整个集群的NodePort能被唯一分配
portallocatorcontroller.NewRepair
```

- 首次运行repairClusterIPs 和 repairNodePorts

```Go
// 对Service ClusterIP 的修复及检查
// RunOnce代码有点长，就不贴了，走了一遍流程
// run all of the controllers once prior to returning from Start.
if err := repairClusterIPs.RunOnce(); err != nil {
   // If we fail to repair cluster IPs apiserver is useless. We should restart and retry.
   klog.Fatalf("Unable to perform initial IP allocation check: %v", err)
}
// 对Service NodePort 的修复及检查
// RunOnce代码有点长，就不贴了，走了一遍流程
if err := repairNodePorts.RunOnce(); err != nil {
   // If we fail to repair node ports apiserver is useless. We should restart and retry.
   klog.Fatalf("Unable to perform initial service nodePort check: %v", err)
}
```

- 定期执行 bootstrap controller 主要的四个功能(reconciliation) 

```Swift
// 开始异步执行bootstrap controller负责的功能
c.runner = async.NewRunner(c.RunKubernetesNamespaces, c.RunKubernetesService, repairClusterIPs.RunUntil, repairNodePorts.RunUntil)
c.runner.Start()
```

#### RunKubernetesNamespaces：

```Swift
// RunKubernetesNamespaces periodically makes sure that all internal namespaces exist
func (c *Controller) RunKubernetesNamespaces(ch chan struct{}) {
   wait.Until(func() {
      // Loop the system namespace list, and create them if they do not exist
      for _, ns := range c.SystemNamespaces {
         if err := createNamespaceIfNeeded(c.NamespaceClient, ns); err != nil {
            runtime.HandleError(fmt.Errorf("unable to create required kubernetes system namespace %s: %v", ns, err))
         }
      }
   }, c.SystemNamespacesInterval, ch)
}
```

#### RunKubernetesService：

```Swift
// RunKubernetesService periodically updates the kubernetes service
func (c *Controller) RunKubernetesService(ch chan struct{}) {
   // wait until process is ready
   // 需要等到进程ready，才可以执行后面的逻辑
   wait.PollImmediateUntil(100*time.Millisecond, func() (bool, error) {
      var code int
      c.readyzClient.Get().AbsPath("/readyz").Do(context.TODO()).StatusCode(&code)
      return code == http.StatusOK, nil
   }, ch)
   // 一直运行，直到channel close
   wait.NonSlidingUntil(func() {
      // Service definition is not reconciled after first
      // run, ports and type will be corrected only during
      // start.
      if err := c.UpdateKubernetesService(false); err != nil {
         runtime.HandleError(fmt.Errorf("unable to sync kubernetes service: %v", err))
      }
   }, c.EndpointInterval, ch)
}

// UpdateKubernetesService attempts to update the default Kube service.
func (c *Controller) UpdateKubernetesService(reconcile bool) error {
   // Update service & endpoint records.
   // TODO: when it becomes possible to change this stuff,
   // stop polling and start watching.
   // TODO: add endpoints of all replicas, not just the elected master.
   if err := createNamespaceIfNeeded(c.NamespaceClient, metav1.NamespaceDefault); err != nil {
      return err
   }
   // 创建service
   servicePorts, serviceType := createPortAndServiceSpec(c.ServicePort, c.PublicServicePort, c.KubernetesServiceNodePort, "https", c.ExtraServicePorts)
   if err := c.CreateOrUpdateMasterServiceIfNeeded(kubernetesServiceName, c.ServiceIP, servicePorts, serviceType, reconcile); err != nil {
      return err
   }
   // 创建endpoints
   endpointPorts := createEndpointPortSpec(c.PublicServicePort, "https", c.ExtraEndpointPorts)
   if err := c.EndpointReconciler.ReconcileEndpoints(kubernetesServiceName, c.PublicIP, endpointPorts, reconcile); err != nil {
      return err
   }
   return nil
}
```

#### repairClusterIPs.RunUntil：

#### repairNodePorts.RunUntil：

// 两个函数都会一直执行，知道channel close

```Swift
// RunUntil starts the controller until the provided ch is closed.
func (c *Repair) RunUntil(ch chan struct{}) {
   wait.Until(func() {
      if err := c.RunOnce(); err != nil {
         runtime.HandleError(err)
      }
   }, c.interval, ch)
}
```