# 【k8s源码阅读】kube-apiserver 限流

> 源码地址：git@github.com:kubernetes/kubernetes.git
>
> version: 1.21.3

k8s限流方案：

- webserver级别限流-`--max-requests-inflight` `--max-mutating-request-inflight`
- client端限流-设置QPS
- api级别的限流-APF（api priority and fairness）

## 一、webserver级别限流-MaxInFlightLimit

官方文档-限流参数

```shell
max-mutating-requests-inflight int Default: 200
This and --max-requests-inflight are summed to determine the server's total concurrency limit (which must be positive) if --enable-priority-and-fairness is true. Otherwise, this flag limits the maximum number of mutating requests in flight, or a zero value disables the limit completely.

max-requests-inflight int Default: 400
This and --max-mutating-requests-inflight are summed to determine the server's total concurrency limit (which must be positive) if --enable-priority-and-fairness is true. Otherwise, this flag limits the maximum number of non-mutating requests in flight, or a zero value disables the limit completely.
```

从文档以及下面代码中对参数的定义：

两个值的类型都是限制kube-apiserver接受并发请求的个数，一个是mutating，一个是非mutating

另外还有一个限流参数： `--enable-priority-and-fairness` APF之后解读。如果开启APF，则两个限流总请求数相加为api-server的总的请求限制。

### 1. MaxInFlightLimit限流参数声明

代码地址：**cmd/kube-apiserver/app/server.go**

```
server.NewAPIServerCommand
|--options.NewServerRunOptions
   ｜--genericoptions.NewServerRunOptions
       |--server.NewConfig
       |--MaxRequestsInFlight
       |--MaxMutatingRequestsInFlight
```

这里简单描述了`--max-requests-inflight`  `--max-mutating-requests-inflight`两个参数的默认值设置。

这里通过为kube-apiserver所有参数设置默认值时，设置了这两个参数。首先初始化`server.NewConfig`函数里就设置了默认的

`MaxRequestsInFlight=400` `MaxMutatingRequestsInFlight=200`

```go
// vendor/k8s.io/apiserver/pkg/server/config.go
// NewConfig returns a Config struct with the default values
func NewConfig(codecs serializer.CodecFactory) *Config {
  ...
	return &Config{
		Serializer:                  codecs,
		BuildHandlerChainFunc:       DefaultBuildHandlerChain,
    ...
		MaxRequestsInFlight:         400,
		MaxMutatingRequestsInFlight: 200,
		...
		}
```

代码地址：vendor/k8s.io/apiserver/pkg/server/config.go

```go
// Config is a structure used to configure a GenericAPIServer.
// Its members are sorted roughly in order of importance for composers.
type Config struct {
  ...
	// MaxRequestsInFlight is the maximum number of parallel non-long-running requests. Every further
	// request has to wait. Applies only to non-mutating requests.
	MaxRequestsInFlight int
	// MaxMutatingRequestsInFlight is the maximum number of parallel mutating requests. Every further
	// request has to wait.
	MaxMutatingRequestsInFlight int
	...
}
```

从参数定义里看到： 限流是不包括`long-running requests`

### 2. MaxInFlightLimit限流的处理流程

kube-apiserver的请求路径定义在`DefaultBuildHandlerChain`，同样是初始化Config时进行注册的

```go
// vendor/k8s.io/apiserver/pkg/server/config.go
// NewConfig returns a Config struct with the default values
func NewConfig(codecs serializer.CodecFactory) *Config {
    ...
	return &Config{
		Serializer:                  codecs,
		BuildHandlerChainFunc:       DefaultBuildHandlerChain,
    ...
 }
```

代码路径：vendor/k8s.io/apiserver/pkg/server/config.go

```go
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "authorization")

  // 这里如果c.FlowControl有值， 走APF限流流程
	if c.FlowControl != nil {
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl)
		handler = filterlatency.TrackStarted(handler, "priorityandfairness")
	} else {
  // 判断MaxInFlightLimit限流  
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}

	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "impersonation")
	...
}	
```

代码路径： vendor/k8s.io/apiserver/pkg/server/filters/maxinflight.go

```go
// 
// WithMaxInFlightLimit limits the number of in-flight requests to buffer size of the passed in channel.
func WithMaxInFlightLimit(
	handler http.Handler,
	nonMutatingLimit int,
	mutatingLimit int,
	longRunningRequestCheck apirequest.LongRunningRequestCheck,
) http.Handler {
  // 如果限流参数配置为0, 直接返回不做限流
	if nonMutatingLimit == 0 && mutatingLimit == 0 {
		return handler
	}
  // 通过channel做限流，容量分别是限流参数
	var nonMutatingChan chan bool
	var mutatingChan chan bool
	if nonMutatingLimit != 0 {
		nonMutatingChan = make(chan bool, nonMutatingLimit)
		watermark.readOnlyObserver.SetX1(float64(nonMutatingLimit))
	}
	if mutatingLimit != 0 {
		mutatingChan = make(chan bool, mutatingLimit)
		watermark.mutatingObserver.SetX1(float64(mutatingLimit))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // 获取http请求信息
		ctx := r.Context()
    // 转换成kube-apiserver类型的请求
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no RequestInfo found in context, handler chain must be wrong"))
			return
		}

		// Skip tracking long running events.
    // 跳过longRunningRequest 什么请求是longRunningRequest， log,watch?
		if longRunningRequestCheck != nil && longRunningRequestCheck(r, requestInfo) {
			handler.ServeHTTP(w, r)
			return
		}

		var c chan bool
		isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb)
		if isMutatingRequest {
			c = mutatingChan
		} else {
			c = nonMutatingChan
		}

		if c == nil {
			handler.ServeHTTP(w, r)
		} else {

			select {
      // 如果可以写成功，说明channel有空间，可以处理请求
			case c <- true:
				// We note the concurrency level both while the
				// request is being served and after it is done being
				// served, because both states contribute to the
				// sampled stats on concurrency.
				if isMutatingRequest {
					watermark.recordMutating(len(c))
				} else {
					watermark.recordReadOnly(len(c))
				}
        // 最后读取channel的值，释放channel，这样缓存channel的有效容量会加1
				defer func() {
					<-c
					if isMutatingRequest {
						watermark.recordMutating(len(c))
					} else {
						watermark.recordReadOnly(len(c))
					}
				}()
				handler.ServeHTTP(w, r)

			default:
        // 如果限流，走这个逻辑，并且判断如果是system:master用户，不做限制
				// at this point we're about to return a 429, BUT not all actors should be rate limited.  A system:master is so powerful
				// that they should always get an answer.  It's a super-admin or a loopback connection.
				if currUser, ok := apirequest.UserFrom(ctx); ok {
					for _, group := range currUser.GetGroups() {
						if group == user.SystemPrivilegedGroup {
							handler.ServeHTTP(w, r)
							return
						}
					}
				}
        // 达到限流标准，开始限流
				// We need to split this data between buckets used for throttling.
        // 记录被丢弃的请求
				if isMutatingRequest {
					metrics.DroppedRequests.WithContext(ctx).WithLabelValues(metrics.MutatingKind).Inc()
				} else {
					metrics.DroppedRequests.WithContext(ctx).WithLabelValues(metrics.ReadOnlyKind).Inc()
				}
				metrics.RecordRequestTermination(r, requestInfo, metrics.APIServerComponent, http.StatusTooManyRequests)
				// 返回429 status indicating "Too Many Requests"
        tooManyRequests(r, w)
			}
		}
	})
}

// StartMaxInFlightWatermarkMaintenance starts the goroutines to observe and maintain watermarks for max-in-flight
// requests.
func StartMaxInFlightWatermarkMaintenance(stopCh <-chan struct{}) {
	startWatermarkMaintenance(watermark, stopCh)
}

func tooManyRequests(req *http.Request, w http.ResponseWriter) {
	// Return a 429 status indicating "Too Many Requests"
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, "Too many requests, please try again later.", http.StatusTooManyRequests)
}
```

### 3. Q&A

（1）**什么是long-runing-request**

全局搜：longRunningRequest

```go
// 1. 
var longRunningRequestPathMap = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
	"debug":       true,
}
// 2.
// watches are expected to handle storage disruption gracefully,
// both on the server-side (by terminating the watch connection)
// and on the client side (by restarting the watch)
var longRunningFilter = genericfilters.BasicLongRunningRequestCheck(sets.NewString("watch"), sets.NewString())

// 3.
// BasicLongRunningRequestCheck returns true if the given request has one of the specified verbs or one of the specified subresources, or is a profiler request.
func BasicLongRunningRequestCheck(longRunningVerbs, longRunningSubresources sets.String) apirequest.LongRunningRequestCheck {
	return func(r *http.Request, requestInfo *apirequest.RequestInfo) bool {
		if longRunningVerbs.Has(requestInfo.Verb) {
			return true
		}
		if requestInfo.IsResourceRequest && longRunningSubresources.Has(requestInfo.Subresource) {
			return true
		}
		if !requestInfo.IsResourceRequest && strings.HasPrefix(requestInfo.Path, "/debug/pprof/") {
			return true
		}
		return false
	}
}
```

**watch,attach,portforward,debug**类的请求和**pprof**的请求属于long-runing-request请求

（2）**什么操作属于mutating类操作**

```go
// staging/src/k8s.io/apiserver/pkg/server/filters/maxinflight.go&L50
var nonMutatingRequestVerbs = sets.NewString("get", "list", "watch")
```

### 4. 总结：

- kube-apiserver限流的处理流程是在认证之后，鉴权之前

- 限流中的两个参数，一个是作用于mutating类的请求，一个是作用于非mutating类的请求

- 限流的实现，申请一个限流参数容量大小的channel做缓存，当请求到达时，占用一个channel，请求处理完之后，释放一个channel的坑位。所以kube-apiserver限流参数值中的值不是每秒的请求数而是缓存channel容量

- long-running-request和特权用户的请求，是不受限流控制的

## 二、 api级别的限流-APF

前面server级别的限流方案将请求分为两类mutating和非mutating（readonly）请求。可以看出限流方案比较简单，粒度较粗。

（当某个客户端发生错误或者使用不当时，触发限流，导致其他客户端同样受到波及）。因此社区里出现一套更细致的限流方案APF。

**API** **Priority and Fairness**

对请求进行更细粒度的划分，保证高优先级请求

**Priority**：请求分优先级，高优先级别请求比低优先级请求处理优先

**Fairness**：同级别的请求处理被公平对待

具体APF使用以及实现，请参考官方文档：https://kubernetes.io/docs/concepts/cluster-administration/flow-control/

> 从官方文档的描述中，可以看到APF的概念很多，metrics指标也很多（**metrics指标多更容易分析kube-apiserver的请求分布情况**），源码实现也是挺复杂

> APF限流方案在k8s1.18默认开启

### **1. APF 介绍**

> 参考官方文档：https://kubernetes.io/docs/concepts/cluster-administration/flow-control/

资源介绍：

https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/cluster-resources/flow-schema-v1beta2/

https://kubernetes.io/zh-cn/docs/reference/kubernetes-api/cluster-resources/priority-level-configuration-v1beta2/

### 2. APF处理流程

根据上述处理流程，主要判断FlowControl是否为nil

```go
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "authorization")

  // 这里如果c.FlowControl有值， 走APF限流流程
	if c.FlowControl != nil {
		handler = filterlatency.TrackCompleted(handler)
		handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl)
		handler = filterlatency.TrackStarted(handler, "priorityandfairness")
	} else {
  // 判断MaxInFlightLimit限流  
		handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
	}
	handler = filterlatency.TrackCompleted(handler)
	handler = genericapifilters.WithImpersonation(handler, c.Authorization.Authorizer, c.Serializer)
	handler = filterlatency.TrackStarted(handler, "impersonation")
	...
}	
```

代码地址：vendor/k8s.io/apiserver/pkg/server/filters/priority-and-fairness.go

```go
// 处理流程倒是不复杂，流程比较清晰，与MaxInFlightLimit类似
// WithPriorityAndFairness limits the number of in-flight
// requests in a fine-grained way.
func WithPriorityAndFairness(
	handler http.Handler,
	longRunningRequestCheck apirequest.LongRunningRequestCheck,
	fcIfc utilflowcontrol.Interface,
) http.Handler {
	if fcIfc == nil {
		klog.Warningf("priority and fairness support not found, skipping")
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // 获取请求上下文
		ctx := r.Context()
    // 请求信息转换
		requestInfo, ok := apirequest.RequestInfoFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no RequestInfo found in context"))
			return
		}
		user, ok := apirequest.UserFrom(ctx)
		if !ok {
			handleError(w, r, fmt.Errorf("no User found in context"))
			return
		}

		// Skip tracking long running requests.
    // 可以看到APF同样对longRunningRequest不做限流
		if longRunningRequestCheck != nil && longRunningRequestCheck(r, requestInfo) {
			klog.V(6).Infof("Serving RequestInfo=%#+v, user.Info=%#+v as longrunning\n", requestInfo, user)
			handler.ServeHTTP(w, r)
			return
		}

    // 声明以及初始化APF相关参数
		var classification *PriorityAndFairnessClassification
		note := func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration) {
			classification = &PriorityAndFairnessClassification{
				FlowSchemaName:    fs.Name,
				FlowSchemaUID:     fs.UID,
				PriorityLevelName: pl.Name,
				PriorityLevelUID:  pl.UID}
		}

		var served bool
		isMutatingRequest := !nonMutatingRequestVerbs.Has(requestInfo.Verb)
		noteExecutingDelta := func(delta int32) {
			if isMutatingRequest {
				watermark.recordMutating(int(atomic.AddInt32(&atomicMutatingExecuting, delta)))
			} else {
				watermark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyExecuting, delta)))
			}
		}
		noteWaitingDelta := func(delta int32) {
			if isMutatingRequest {
				waitingMark.recordMutating(int(atomic.AddInt32(&atomicMutatingWaiting, delta)))
			} else {
				waitingMark.recordReadOnly(int(atomic.AddInt32(&atomicReadOnlyWaiting, delta)))
			}
		}
		execute := func() {
			noteExecutingDelta(1)
			defer noteExecutingDelta(-1)
			served = true
			innerCtx := context.WithValue(ctx, priorityAndFairnessKey, classification)
			innerReq := r.Clone(innerCtx)
			setResponseHeaders(classification, w)

			handler.ServeHTTP(w, innerReq)
		}
		digest := utilflowcontrol.RequestDigest{RequestInfo: requestInfo, User: user}
    // 调用flowcontroller方法Handle处理请求
    // 也是APF核心的限流处理流程
		fcIfc.Handle(ctx, digest, note, func(inQueue bool) {
			if inQueue {
				noteWaitingDelta(1)
			} else {
				noteWaitingDelta(-1)
			}
		}, execute)
    // 限流处理逻辑
		if !served {
			setResponseHeaders(classification, w)

			if isMutatingRequest {
				epmetrics.DroppedRequests.WithContext(ctx).WithLabelValues(epmetrics.MutatingKind).Inc()
			} else {
				epmetrics.DroppedRequests.WithContext(ctx).WithLabelValues(epmetrics.ReadOnlyKind).Inc()
			}
			epmetrics.RecordRequestTermination(r, requestInfo, epmetrics.APIServerComponent, http.StatusTooManyRequests)
			tooManyRequests(r, w)
		}

	})
}
```



代码路径： vendor/k8s.io/apiserver/pkg/util/flowcontrol/apf_filter.go

```Go
func (cfgCtlr *configController) Handle(ctx context.Context, requestDigest RequestDigest,

   noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration),

   queueNoteFn fq.QueueNoteFn,

   execFn func()) {

   // 处理请求

   fs, pl, isExempt, req, startWaitingTime := cfgCtlr.startRequest(ctx, requestDigest, queueNoteFn)

   

   queued := startWaitingTime != time.Time{}

   noteFn(fs, pl)

   if req == nil {

      if queued {

         metrics.ObserveWaitingDuration(ctx, pl.Name, fs.Name, strconv.FormatBool(req != nil), time.Since(startWaitingTime))

      }

      klog.V(7).Infof("Handle(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, isExempt=%v, reject", requestDigest, fs.Name, fs.Spec.DistinguisherMethod, pl.Name, isExempt)

      return

   }

   ...

 }  
```

startRequest：

代码路径： vendor/k8s.io/apiserver/pkg/util/flowcontrol/apf_controller.go

```Go
// startRequest classifies and, if appropriate, enqueues the request.

// Returns a nil Request if and only if the request is to be rejected.

// The returned bool indicates whether the request is exempt from

// limitation.  The startWaitingTime is when the request started

// waiting in its queue, or `Time{}` if this did not happen.

func (cfgCtlr *configController) startRequest(ctx context.Context, rd RequestDigest, queueNoteFn fq.QueueNoteFn) (fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration, isExempt bool, req fq.Request, startWaitingTime time.Time) {

   klog.V(7).Infof("startRequest(%#+v)", rd)

   cfgCtlr.lock.Lock()

   defer cfgCtlr.lock.Unlock()

   var selectedFlowSchema, catchAllFlowSchema *flowcontrol.FlowSchema

   // 请求分类

   for _, fs := range cfgCtlr.flowSchemas {

      if matchesFlowSchema(rd, fs) {

         selectedFlowSchema = fs

         break

      }

      if fs.Name == flowcontrol.FlowSchemaNameCatchAll {

         catchAllFlowSchema = fs

      }

   }

   if selectedFlowSchema == nil {

      // This should never happen. If the requestDigest's User is a part of

      // system:authenticated or system:unauthenticated, the catch-all flow

      // schema should match it. However, if that invariant somehow fails,

      // fallback to the catch-all flow schema anyway.

      if catchAllFlowSchema == nil {

         // This should absolutely never, ever happen! APF guarantees two

         // undeletable flow schemas at all times: an exempt flow schema and a

         // catch-all flow schema.

         panic(fmt.Sprintf("no fallback catch-all flow schema found for request %#+v and user %#+v", rd.RequestInfo, rd.User))

      }

      selectedFlowSchema = catchAllFlowSchema

      klog.Warningf("no match found for request %#+v and user %#+v; selecting catchAll=%s as fallback flow schema", rd.RequestInfo, rd.User, fcfmt.Fmt(selectedFlowSchema))

   }

   plName := selectedFlowSchema.Spec.PriorityLevelConfiguration.Name

   // 获取对应flow流优先级信息

   plState := cfgCtlr.priorityLevelStates[plName]

   if plState.pl.Spec.Type == flowcontrol.PriorityLevelEnablementExempt {

      klog.V(7).Infof("startRequest(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, immediate", rd, selectedFlowSchema.Name, selectedFlowSchema.Spec.DistinguisherMethod, plName)

      return selectedFlowSchema, plState.pl, true, immediateRequest{}, time.Time{}

   }

   var numQueues int32

   // queues 数量

   if plState.pl.Spec.Limited.LimitResponse.Type == flowcontrol.LimitResponseTypeQueue {

      numQueues = plState.pl.Spec.Limited.LimitResponse.Queuing.Queues

   }

   var flowDistinguisher string

   var hashValue uint64

   if numQueues > 1 {

      flowDistinguisher = computeFlowDistinguisher(rd, selectedFlowSchema.Spec.DistinguisherMethod)

      hashValue = hashFlowID(selectedFlowSchema.Name, flowDistinguisher)

   }

   // 请求入队

   startWaitingTime = time.Now()

   klog.V(7).Infof("startRequest(%#+v) => fsName=%q, distMethod=%#+v, plName=%q, numQueues=%d", rd, selectedFlowSchema.Name, selectedFlowSchema.Spec.DistinguisherMethod, plName, numQueues)

   req, idle := plState.queues.StartRequest(ctx, hashValue, flowDistinguisher, selectedFlowSchema.Name, rd.RequestInfo, rd.User, queueNoteFn)

   if idle {

      cfgCtlr.maybeReapLocked(plName, plState)

   }

   return selectedFlowSchema, plState.pl, false, req, startWaitingTime

}
```

代码路径：staging/src/k8s.io/apiserver/pkg/util/flowcontrol/fairqueuing/queueset/queueset.go

```Go
// StartRequest begins the process of handling a request.  We take the

// approach of updating the metrics about total requests queued and

// executing at each point where there is a change in that quantity,

// because the metrics --- and only the metrics --- track that

// quantity per FlowSchema.

func (qs *queueSet) StartRequest(ctx context.Context, hashValue uint64, flowDistinguisher, fsName string, descr1, descr2 interface{}, queueNoteFn fq.QueueNoteFn) (fq.Request, bool) {

   qs.lockAndSyncTime()

   defer qs.lock.Unlock()

   var req *request



   // ========================================================================

   // Step 0:

   // Apply only concurrency limit, if zero queues desired

   if qs.qCfg.DesiredNumQueues < 1 {

      if qs.totRequestsExecuting >= qs.dCfg.ConcurrencyLimit {

         klog.V(5).Infof("QS(%s): rejecting request %q %#+v %#+v because %d are executing and the limit is %d", qs.qCfg.Name, fsName, descr1, descr2, qs.totRequestsExecuting, qs.dCfg.ConcurrencyLimit)

         metrics.AddReject(ctx, qs.qCfg.Name, fsName, "concurrency-limit")

         return nil, qs.isIdleLocked()

      }

      req = qs.dispatchSansQueueLocked(ctx, flowDistinguisher, fsName, descr1, descr2)

      return req, false

   }



   // ========================================================================

   // Step 1:

   // 1) Start with shuffle sharding, to pick a queue.

   // 2) Reject old requests that have been waiting too long

   // 3) Reject current request if there is not enough concurrency shares and

   // we are at max queue length

   // 4) If not rejected, create a request and enqueue

   req = qs.timeoutOldRequestsAndRejectOrEnqueueLocked(ctx, hashValue, flowDistinguisher, fsName, descr1, descr2, queueNoteFn)

   // req == nil means that the request was rejected - no remaining

   // concurrency shares and at max queue length already

   if req == nil {

      klog.V(5).Infof("QS(%s): rejecting request %q %#+v %#+v due to queue full", qs.qCfg.Name, fsName, descr1, descr2)

      metrics.AddReject(ctx, qs.qCfg.Name, fsName, "queue-full")

      return nil, qs.isIdleLocked()

   }



   // ========================================================================

   // Step 2:

   // The next step is to invoke the method that dequeues as much

   // as possible.

   // This method runs a loop, as long as there are non-empty

   // queues and the number currently executing is less than the

   // assured concurrency value.  The body of the loop uses the

   // fair queuing technique to pick a queue and dispatch a

   // request from that queue.

   qs.dispatchAsMuchAsPossibleLocked()



   // ========================================================================

   // Step 3:



   // Set up a relay from the context's Done channel to the world

   // of well-counted goroutines. We Are Told that every

   // request's context's Done channel gets closed by the time

   // the request is done being processed.

   doneCh := ctx.Done()



   // Retrieve the queueset configuration name while we have the lock

   // and use it in the goroutine below.

   configName := qs.qCfg.Name



   if doneCh != nil {

      qs.preCreateOrUnblockGoroutine()

      go func() {

         defer runtime.HandleCrash()

         qs.goroutineDoneOrBlocked()

         _ = <-doneCh

         // Whatever goroutine unblocked the preceding receive MUST
         // have already either (a) incremented qs.counter or (b)
         // known that said counter is not actually counting or (c)
         // known that the count does not need to be accurate.
         // BTW, the count only needs to be accurate in a test that
         // uses FakeEventClock::Run().
         klog.V(6).Infof("QS(%s): Context of request %q %#+v %#+v is Done", configName, fsName, descr1, descr2)
         qs.cancelWait(req)
         qs.goroutineDoneOrBlocked()
      }()
   }
   return req, false
}
```



```Go
// timeoutOldRequestsAndRejectOrEnqueueLocked -->
         -> chooseQueueIndexLocked
         -> removeTimedOutRequestsFromQueueLocked
         -> rejectOrEnqueueLocked
// shuffle sharding 选择一个队列
// chooseQueueIndexLocked uses shuffle sharding to select a queue index
// using the given hashValue and the shuffle sharding parameters of the queueSet.
func (qs *queueSet) chooseQueueIndexLocked(hashValue uint64, descr1, descr2 interface{}) int {
   bestQueueIdx := -1
   bestQueueLen := int(math.MaxInt32)
   // the dealer uses the current desired number of queues, which is no larger than the number in `qs.queues`.
   qs.dealer.Deal(hashValue, func(queueIdx int) {
      thisLen := len(qs.queues[queueIdx].requests)
      klog.V(7).Infof("QS(%s): For request %#+v %#+v considering queue %d of length %d", qs.qCfg.Name, descr1, descr2, queueIdx, thisLen)

      if thisLen < bestQueueLen {

         bestQueueIdx, bestQueueLen = queueIdx, thisLen

      }

   })

   klog.V(6).Infof("QS(%s) at r=%s v=%.9fs: For request %#+v %#+v chose queue %d, had %d waiting & %d executing", qs.qCfg.Name, qs.clock.Now().Format(nsTimeFmt), qs.virtualTime, descr1, descr2, bestQueueIdx, bestQueueLen, qs.queues[bestQueueIdx].requestsExecuting)

   return bestQueueIdx

}
```

### 3.  APF  flowcontroller

初始化：

```Go
// cmd/kube-apiserver/app/server.go

// buildGenericConfig

if utilfeature.DefaultFeatureGate.Enabled(genericfeatures.APIPriorityAndFairness) && s.GenericServerRunOptions.EnablePriorityAndFairness {

   genericConfig.FlowControl = BuildPriorityAndFairness(s, clientgoExternalClient, versionedInformers)

}
```

flowcontroller声明：

代码路径：vendor/k8s.io/apiserver/pkg/util/flowcontrol/apf_filter.go

```Go
// Interface defines how the API Priority and Fairness filter interacts with the underlying system.

type Interface interface {

   // Handle takes care of queuing and dispatching a request

   // characterized by the given digest.  The given `noteFn` will be

   // invoked with the results of request classification.  If the

   // request is queued then `queueNoteFn` will be called twice,

   // first with `true` and then with `false`; otherwise

   // `queueNoteFn` will not be called at all.  If Handle decides

   // that the request should be executed then `execute()` will be

   // invoked once to execute the request; otherwise `execute()` will

   // not be invoked.

   Handle(ctx context.Context,

      requestDigest RequestDigest,

      noteFn func(fs *flowcontrol.FlowSchema, pl *flowcontrol.PriorityLevelConfiguration),

      queueNoteFn fq.QueueNoteFn,

      execFn func(),

   )
   // MaintainObservations is a helper for maintaining statistics.

   MaintainObservations(stopCh <-chan struct{})

   // Run monitors config objects from the main apiservers and causes

   // any needed changes to local behavior.  This method ceases

   // activity and returns after the given channel is closed.

   Run(stopCh <-chan struct{}) error
   // Install installs debugging endpoints to the web-server.

   Install(c *mux.PathRecorderMux)

}
```









