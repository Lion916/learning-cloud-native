# 【k8s源码阅读】kube-scheduler cache

Cache中是已经调度的Pod（包括假定调度的Pod）。Cache并不是仅仅为了存储已调度的Pod方便查找，同时为调度提供能非常重要的状态信息。

## cache实例化：

```
runCommand
-->Setup(ctx, opts, registryOptions...)
   -->scheduler.New
      --> schedulerCache := internalcache.New(30*time.Second, stopEverything)
```

```go
// pkg/scheduler/internal/cache/cache.go
// New returns a Cache implementation.
// It automatically starts a go routine that manages expiration of assumed pods.
// "ttl" is how long the assumed pod will get expired.
// "stop" is the channel that would close the background goroutine.
func New(ttl time.Duration, stop <-chan struct{}) Cache {
   cache := newSchedulerCache(ttl, cleanAssumedPeriod, stop)
   cache.run()
   return cache
}

func (cache *schedulerCache) run() {
	go wait.Until(cache.cleanupExpiredAssumedPods, cache.period, cache.stop)
}
```

实例化过程中实例化`type schedulerCache struct`结构体，并且调用`run`函数启动cache（只是定期清理过期的AssumedPod）。并但会`Cache`接口

## cache

### cache抽象

```go
// pkg/scheduler/internal/cache/interface.go
type Cache interface {
	// NodeCount returns the number of nodes in the cache.
	// DO NOT use outside of tests.
	NodeCount() int

	// PodCount returns the number of pods in the cache (including those from deleted nodes).
	// DO NOT use outside of tests.
	PodCount() (int, error)

	// AssumePod assumes a pod scheduled and aggregates the pod's information into its node.
	// The implementation also decides the policy to expire pod before being confirmed (receiving Add event).
	// After expiration, its information would be subtracted.
  // 假定Pod,就是将Pod假定调度到指定的Node,但还没有Bind完成。
  // AssumePod会将Pod的资源需求累加到Node上，这样kube-scheduler在调度其他Pod的时候,
  // 就不会占用这部分资源。
	AssumePod(pod *v1.Pod) error

	// FinishBinding signals that cache for assumed pod can be expired
  // Bind是一个异步过程，当Bind完成后需要调用这个接口通知Cache，
  // 如果完成Bind的Pod长时间没有被确认(确认方法是AddPod)，那么Cache就会清理掉假定过期的Pod。
	FinishBinding(pod *v1.Pod) error

	// ForgetPod removes an assumed pod from cache.
	ForgetPod(pod *v1.Pod) error

	// AddPod either confirms a pod if it's assumed, or adds it back if it's expired.
	// If added back, the pod's information would be added again.
	AddPod(pod *v1.Pod) error

	// UpdatePod removes oldPod's information and adds newPod's information.
	UpdatePod(oldPod, newPod *v1.Pod) error

	// RemovePod removes a pod. The pod's information would be subtracted from assigned node.
	RemovePod(pod *v1.Pod) error

	// GetPod returns the pod from the cache with the same namespace and the
	// same name of the specified pod.
	GetPod(pod *v1.Pod) (*v1.Pod, error)

	// IsAssumedPod returns true if the pod is assumed and not expired.
  // 判断Pod是否假定调度
	IsAssumedPod(pod *v1.Pod) (bool, error)

	// AddNode adds overall information about node.
	AddNode(node *v1.Node) error

	// UpdateNode updates overall information about node.
	UpdateNode(oldNode, newNode *v1.Node) error

	// RemoveNode removes overall information about node.
	RemoveNode(node *v1.Node) error

	// UpdateSnapshot updates the passed infoSnapshot to the current contents of Cache.
	// The node info contains aggregated information of pods scheduled (including assumed to be)
	// on this node.
	// The snapshot only includes Nodes that are not deleted at the time this function is called.
	// nodeinfo.Node() is guaranteed to be not nil for all the nodes in the snapshot.
	UpdateSnapshot(nodeSnapshot *Snapshot) error

	// Dump produces a dump of the current cache.
	Dump() *Dump
}
```

Cache的接口设计上可以看出，Cache只缓存了Pod和Node信息，而Pod和Node信息存储在etcd中(可以通过kubectl增删改查)

### cache实现

```go
// nodeInfoListItem holds a NodeInfo pointer and acts as an item in a doubly
// linked list. When a NodeInfo is updated, it goes to the head of the list.
// The items closer to the head are the most recently updated items.
// NodeInfo双向链表
type nodeInfoListItem struct {
	info *framework.NodeInfo
	next *nodeInfoListItem
	prev *nodeInfoListItem
}

type schedulerCache struct {
  // 用来通知schedulerCache停止的chan
	stop   <-chan struct{}
  // 假定Pod一旦完成绑定，就要在指定的时间内确认，否则就会超时，ttl就是指定的过期时间，默认30秒
	ttl    time.Duration
  // 定时清理AssumedPod定时周期
	period time.Duration

	// This mutex guards all fields within this cache struct.
  // schedulerCache利用互斥锁实现协程安全
	mu sync.RWMutex
	// a set of assumed pod keys.
	// The key could further be used to get an entry in podStates.
  // assumed pod set集合
	assumedPods sets.String
	// a map from pod key to podState.
  // podState继承了Pod的API定义，增加了Cache需要的属性
	podStates map[string]*podState
  // 所有的Node，键是Node.Name，值是nodeInfoListItem
	nodes     map[string]*nodeInfoListItem
	// headNode points to the most recently updated NodeInfo in "nodes". It is the
	// head of the linked list.
  // 所有的Node再通过双向链表连接起来
	headNode *nodeInfoListItem
  // 
	nodeTree *nodeTree
	// A map from image name to its imageState.
	imageStates map[string]*imageState
}

type podState struct {
	pod *v1.Pod
	// Used by assumedPod to determinate expiration.
	deadline *time.Time
	// Used to block cache from expiring assumedPod if binding still runs
	bindingFinished bool
}

type imageState struct {
	// Size of the image
	size int64
	// A set of node names for nodes having this image present
	nodes sets.String
}
```

**NodeInfo**

```go
// NodeInfo is node level aggregated information.
type NodeInfo struct {
   // Overall node information.
   node *v1.Node

   // Pods running on the node.
   // 运行在Node上的所有Pod
   Pods []*PodInfo

   // The subset of pods with affinity.
   // Pods的子集，所有的Pod都声明了亲和性
   PodsWithAffinity []*PodInfo

   // The subset of pods with required anti-affinity.
   // 所有的Pod都声明了反亲和性
   PodsWithRequiredAntiAffinity []*PodInfo

   // Ports allocated on the node.
   UsedPorts HostPortInfo

   // Total requested resources of all pods on this node. This includes assumed
   // pods, which scheduler has sent for binding, but may not be scheduled yet.
   // Node上所有Pod的总Request资源，包括假定的Pod
   Requested *Resource
   // Total requested resources of all pods on this node with a minimum value
   // applied to each container's CPU and memory requests. This does not reflect
   // the actual resource requests for this node, but is used to avoid scheduling
   // many zero-request pods onto one node.
   // Pod的容器资源请求有的时候是0，kube-scheduler为这类容器设置默认的资源最小值，并累加到NonZeroRequested.
   // NonZeroRequested等于Requested加上所有按照默认最小值累加的零资源
   // 这并不反映此节点的实际资源请求，而是用于避免将许多零资源请求的Pod调度到一个Node上。
   NonZeroRequested *Resource
   // We store allocatedResources (which is Node.Status.Allocatable.*) explicitly
   // as int64, to avoid conversions and accessing map.
   // Node的可分配的资源量
   Allocatable *Resource

   // ImageStates holds the entry of an image if and only if this image is on the node. The entry can be used for
   // checking an image's existence and advanced usage (e.g., image locality scheduling policy) based on the image
   // state information.
   // 镜像状态
   ImageStates map[string]*ImageStateSummary

   // TransientInfo holds the information pertaining to a scheduling cycle. This will be destructed at the end of
   // scheduling cycle.
   // TODO: @ravig. Remove this once we have a clear approach for message passing across predicates and priorities.
   TransientInfo *TransientSchedulerInfo

   // Whenever NodeInfo changes, generation is bumped.
   // This is used to avoid cloning it if the object didn't change.
   Generation int64
}
```

**nodeTree**

nodeTree是按照区域(zone)将Node组织成树状结构，当需要按区域列举或者全量列举按照区域排序，nodeTree就会用的上。

```go
// nodeTree is a tree-like data structure that holds node names in each zone. Zone names are
// keys to "NodeTree.tree" and values of "NodeTree.tree" are arrays of node names.
// NodeTree is NOT thread-safe, any concurrent updates/reads from it must be synchronized by the caller.
// It is used only by schedulerCache, and should stay as such.
type nodeTree struct {
	tree     map[string][]string // a map from zone (region-zone) to an array of nodes in the zone.
	zones    []string            // a list of all the zones in the tree (keys)
	numNodes int
}
```

**AssumePod()**

当kube-scheduler找到最优的Node调度Pod的时候会调用AssumePod假定Pod调度，在通过另一个协程异步Bind。假定其实就是预先占住资源，kube-scheduler调度下一个Pod的时候不会把这部分资源抢走，直到收到确认消息AddPod确认调度成功，亦或是Bind失败ForgetPod取消假定调度

```go
func (cache *schedulerCache) AssumePod(pod *v1.Pod) error {
  // pod uid
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
  // 如果Pod已经存在，则不能假定调度。因为在Cache中的Pod要么是假定调度的，要么是完成调度的
	if _, ok := cache.podStates[key]; ok {
		return fmt.Errorf("pod %v is in the cache, so can't be assumed", key)
	}

	cache.addPod(pod)
	ps := &podState{
		pod: pod,
	}
  // 把Pod添加到map中，并标记为assumed
	cache.podStates[key] = ps
	cache.assumedPods.Insert(key)
	return nil
}

// Assumes that lock is already acquired.
func (cache *schedulerCache) addPod(pod *v1.Pod) {
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		n = newNodeInfoListItem(framework.NewNodeInfo())
		cache.nodes[pod.Spec.NodeName] = n
	}
  // AddPod就是把Pod的资源累加到NodeInfo中
	n.info.AddPod(pod)
  // 将Node放到schedulerCache.headNode队列头部
	cache.moveNodeInfoToHead(pod.Spec.NodeName)
}
```

**FinishBinding()**

当假定Pod绑定完成后，需要调用FinishBinding通知Cache开始计时，直到假定Pod过期如果依然没有收到AddPod的请求，则将过期假定Pod删除

```go
func (cache *schedulerCache) FinishBinding(pod *v1.Pod) error {
	return cache.finishBinding(pod, time.Now())
}

// finishBinding exists to make tests determinitistic by injecting now as an argument
func (cache *schedulerCache) finishBinding(pod *v1.Pod, now time.Time) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	klog.V(5).Infof("Finished binding for pod %v. Can be expired.", key)
	currState, ok := cache.podStates[key]
	if ok && cache.assumedPods.Has(key) {
		dl := now.Add(cache.ttl)
		currState.bindingFinished = true
		currState.deadline = &dl
	}
	return nil
}
```

**ForgetPod()**

假定Pod预先占用了一些资源，如果之后的操作(比如Bind)有什么错误，就需要取消假定调度，释放出资源

```go
func (cache *schedulerCache) ForgetPod(pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
  // Cache假定Pod的Node名字与传入的Pod的Node名字不一致，则返回错误
  // ?
	currState, ok := cache.podStates[key]
	if ok && currState.pod.Spec.NodeName != pod.Spec.NodeName {
		return fmt.Errorf("pod %v was assumed on %v but assigned to %v", key, pod.Spec.NodeName, currState.pod.Spec.NodeName)
	}

	switch {
	// Only assumed pod can be forgotten.
	case ok && cache.assumedPods.Has(key):
		err := cache.removePod(pod)
		if err != nil {
			return err
		}
		delete(cache.assumedPods, key)
		delete(cache.podStates, key)
	default:
		return fmt.Errorf("pod %v wasn't assumed so cannot be forgotten", key)
	}
	return nil
}
```

**AddPod()**

当Pod Bind成功，kube-scheduler会收到消息，然后调用AddPod确认调度结果

```go
func (cache *schedulerCache) AddPod(pod *v1.Pod) error {
	key, err := framework.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	currState, ok := cache.podStates[key]
	switch {
	case ok && cache.assumedPods.Has(key):
		if currState.pod.Spec.NodeName != pod.Spec.NodeName {
			// The pod was added to a different node than it was assumed to.
			klog.Warningf("Pod %v was assumed to be on %v but got added to %v", key, pod.Spec.NodeName, currState.pod.Spec.NodeName)
			// Clean this up.
			if err = cache.removePod(currState.pod); err != nil {
				klog.Errorf("removing pod error: %v", err)
			}
			cache.addPod(pod)
		}
		delete(cache.assumedPods, key)
		cache.podStates[key].deadline = nil
		cache.podStates[key].pod = pod
	case !ok:
		// Pod was expired. We should add it back.
		cache.addPod(pod)
		ps := &podState{
			pod: pod,
		}
		cache.podStates[key] = ps
	default:
		return fmt.Errorf("pod %v was already in added state", key)
	}
	return nil
}
```

**Run()**

清理过期pod

```go
func (cache *schedulerCache) cleanupExpiredAssumedPods() {
	cache.cleanupAssumedPods(time.Now())
}

// cleanupAssumedPods exists for making test deterministic by taking time as input argument.
// It also reports metrics on the cache size for nodes, pods, and assumed pods.
func (cache *schedulerCache) cleanupAssumedPods(now time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	defer cache.updateMetrics()

	// The size of assumedPods should be small
  // 遍历
	for key := range cache.assumedPods {
		ps, ok := cache.podStates[key]
		if !ok {
			klog.Fatal("Key found in assumed set but not in podStates. Potentially a logical error.")
		}
		if !ps.bindingFinished {
			klog.V(5).Infof("Couldn't expire cache for pod %v/%v. Binding is still in progress.",
				ps.pod.Namespace, ps.pod.Name)
			continue
		}
    // 过期清理
		if now.After(*ps.deadline) {
			klog.Warningf("Pod %s/%s expired", ps.pod.Namespace, ps.pod.Name)
			if err := cache.expirePod(key, ps); err != nil {
				klog.Errorf("ExpirePod failed for %s: %v", key, err)
			}
		}
	}
}
```

**UpdateSnapshot**

快照是对Cache某一时刻的复制，随着时间的推移，Cache的状态在持续更新，kube-scheduler在调度一个Pod的时候需要获取Cache的快照。相比于直接访问Cache，快照可以解决如下几个问题：

快照不会再有任何变化，可以理解为只读，那么访问快照不需要加锁保证保证原子性； 快照和Cache让读写分离，可以避免大范围的锁造成Cache访问性能下降； 虽然快照的状态从创建开始就落后于(因为Cache可能随时都会更新)Cache，但是对于kube-scheduler调度一个Pod来说是没问题的

```go
// Snapshot is a snapshot of cache NodeInfo and NodeTree order. The scheduler takes a
// snapshot at the beginning of each scheduling cycle and uses it for its operations in that cycle.
// 快照保存node信息 NodeInfo and NodeTree order
type Snapshot struct {
	// nodeInfoMap a map of node name to a snapshot of its NodeInfo.
	nodeInfoMap map[string]*framework.NodeInfo
	// nodeInfoList is the list of nodes as ordered in the cache's nodeTree.
	nodeInfoList []*framework.NodeInfo
	// havePodsWithAffinityNodeInfoList is the list of nodes with at least one pod declaring affinity terms.
	havePodsWithAffinityNodeInfoList []*framework.NodeInfo
	// havePodsWithRequiredAntiAffinityNodeInfoList is the list of nodes with at least one pod declaring
	// required anti-affinity terms.
	havePodsWithRequiredAntiAffinityNodeInfoList []*framework.NodeInfo
	generation                                   int64
}
```



```go
// UpdateSnapshot takes a snapshot of cached NodeInfo map. This is called at
// beginning of every scheduling cycle.
// The snapshot only includes Nodes that are not deleted at the time this function is called.
// nodeinfo.Node() is guaranteed to be not nil for all the nodes in the snapshot.
// This function tracks generation number of NodeInfo and updates only the
// entries of an existing snapshot that have changed after the snapshot was taken.
func (cache *schedulerCache) UpdateSnapshot(nodeSnapshot *Snapshot) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	balancedVolumesEnabled := utilfeature.DefaultFeatureGate.Enabled(features.BalanceAttachedNodeVolumes)

	// Get the last generation of the snapshot.
  // 快照版本
	snapshotGeneration := nodeSnapshot.generation

  // 是否需要更新一下列表，默认false
	// NodeInfoList and HavePodsWithAffinityNodeInfoList must be re-created if a node was added
	// or removed from the cache.
	updateAllLists := false
	// HavePodsWithAffinityNodeInfoList must be re-created if a node changed its
	// status from having pods with affinity to NOT having pods with affinity or the other
	// way around.
	updateNodesHavePodsWithAffinity := false
	// HavePodsWithRequiredAntiAffinityNodeInfoList must be re-created if a node changed its
	// status from having pods with required anti-affinity to NOT having pods with required
	// anti-affinity or the other way around.
	updateNodesHavePodsWithRequiredAntiAffinity := false

	// Start from the head of the NodeInfo doubly linked list and update snapshot
	// of NodeInfos updated after the last snapshot.
  // 遍历链表
	for node := cache.headNode; node != nil; node = node.next {
    // 说明Node的状态已经在nodeSnapshot中了，因为但凡Node有任何更新，那么NodeInfo.Generation 
    // 肯定会大于snapshotGeneration，同时该Node后面的所有Node也不用在遍历了，因为他们的版本更低
    // 更新列表时，版本最新的是headNode
		if node.info.Generation <= snapshotGeneration {
			// all the nodes are updated before the existing snapshot. We are done.
			break
		}
    // 
		if balancedVolumesEnabled && node.info.TransientInfo != nil {
			// Transient scheduler info is reset here.
			node.info.TransientInfo.ResetTransientSchedulerInfo()
		}
    // node.info.Node()获取*v1.Node
		if np := node.info.Node(); np != nil {
      // 如果nodeSnapshot中没有该Node，则在nodeSnapshot中创建Node，并标记更新全量列表，因为创建了新的Node
			existing, ok := nodeSnapshot.nodeInfoMap[np.Name]
			if !ok {
				updateAllLists = true
				existing = &framework.NodeInfo{}
				nodeSnapshot.nodeInfoMap[np.Name] = existing
			}
      // 克隆NodeInfo，这个比较好理解，肯定不能简单的把指针设置过去，这样会造成多协程读写同一个对象
      // 因为克隆操作比较重，所以能少做就少做，这也是利用Generation实现增量更新的原因
			clone := node.info.Clone()
			// We track nodes that have pods with affinity, here we check if this node changed its
			// status from having pods with affinity to NOT having pods with affinity or the other
			// way around.
      // 如果Pod以前或者现在有任何亲和性声明，则需要更新nodeSnapshot中的亲和性列表
			if (len(existing.PodsWithAffinity) > 0) != (len(clone.PodsWithAffinity) > 0) {
				updateNodesHavePodsWithAffinity = true
			}
      // 同上
			if (len(existing.PodsWithRequiredAntiAffinity) > 0) != (len(clone.PodsWithRequiredAntiAffinity) > 0) {
				updateNodesHavePodsWithRequiredAntiAffinity = true
			}
			// We need to preserve the original pointer of the NodeInfo struct since it
			// is used in the NodeInfoList, which we may not update.
      // 将NodeInfo的拷贝更新到nodeSnapshot中
			*existing = *clone
		}
	}
	// Update the snapshot generation with the latest NodeInfo generation.
  // 拿到最新版本
  // Cache的表头Node的版本是最新的，所以也就代表了此时更新镜像后镜像的版本了
	if cache.headNode != nil {
		nodeSnapshot.generation = cache.headNode.info.Generation
	}

	// Comparing to pods in nodeTree.
	// Deleted nodes get removed from the tree, but they might remain in the nodes map
	// if they still have non-deleted Pods.
  // 如果nodeSnapshot中node的数量大于nodeTree中的数量，说明有node被删除
  // 所以要从快照的nodeInfoMap中删除已删除的Node，同时标记需要更新node的全量列表
	if len(nodeSnapshot.nodeInfoMap) > cache.nodeTree.numNodes {
		cache.removeDeletedNodesFromSnapshot(nodeSnapshot)
		updateAllLists = true
	}

  // 有一个需要更新，则更新nodeSnapshot中的Node列表
	if updateAllLists || updateNodesHavePodsWithAffinity || updateNodesHavePodsWithRequiredAntiAffinity {
		cache.updateNodeInfoSnapshotList(nodeSnapshot, updateAllLists)
	}
  // 如果此时nodeSnapshot的node列表与nodeTree的数量还不一致，需要再做一次node全列表更新
  // 保险操作，理论上不会发生
	if len(nodeSnapshot.nodeInfoList) != cache.nodeTree.numNodes {
		errMsg := fmt.Sprintf("snapshot state is not consistent, length of NodeInfoList=%v not equal to length of nodes in tree=%v "+
			", length of NodeInfoMap=%v, length of nodes in cache=%v"+
			", trying to recover",
			len(nodeSnapshot.nodeInfoList), cache.nodeTree.numNodes,
			len(nodeSnapshot.nodeInfoMap), len(cache.nodes))
		klog.Error(errMsg)
		// We will try to recover by re-creating the lists for the next scheduling cycle, but still return an
		// error to surface the problem, the error will likely cause a failure to the current scheduling cycle.
		cache.updateNodeInfoSnapshotList(nodeSnapshot, true)
		return fmt.Errorf(errMsg)
	}

	return nil
}

// 执行更新
func (cache *schedulerCache) updateNodeInfoSnapshotList(snapshot *Snapshot, updateAll bool) {
	snapshot.havePodsWithAffinityNodeInfoList = make([]*framework.NodeInfo, 0, cache.nodeTree.numNodes)
	snapshot.havePodsWithRequiredAntiAffinityNodeInfoList = make([]*framework.NodeInfo, 0, cache.nodeTree.numNodes)
	if updateAll {
		// Take a snapshot of the nodes order in the tree
		snapshot.nodeInfoList = make([]*framework.NodeInfo, 0, cache.nodeTree.numNodes)
		nodesList, err := cache.nodeTree.list()
		if err != nil {
			klog.Error(err)
		}
		for _, nodeName := range nodesList {
			if nodeInfo := snapshot.nodeInfoMap[nodeName]; nodeInfo != nil {
				snapshot.nodeInfoList = append(snapshot.nodeInfoList, nodeInfo)
				if len(nodeInfo.PodsWithAffinity) > 0 {
					snapshot.havePodsWithAffinityNodeInfoList = append(snapshot.havePodsWithAffinityNodeInfoList, nodeInfo)
				}
				if len(nodeInfo.PodsWithRequiredAntiAffinity) > 0 {
					snapshot.havePodsWithRequiredAntiAffinityNodeInfoList = append(snapshot.havePodsWithRequiredAntiAffinityNodeInfoList, nodeInfo)
				}
			} else {
				klog.Errorf("node %q exist in nodeTree but not in NodeInfoMap, this should not happen.", nodeName)
			}
		}
	} else {
		for _, nodeInfo := range snapshot.nodeInfoList {
			if len(nodeInfo.PodsWithAffinity) > 0 {
				snapshot.havePodsWithAffinityNodeInfoList = append(snapshot.havePodsWithAffinityNodeInfoList, nodeInfo)
			}
			if len(nodeInfo.PodsWithRequiredAntiAffinity) > 0 {
				snapshot.havePodsWithRequiredAntiAffinityNodeInfoList = append(snapshot.havePodsWithRequiredAntiAffinityNodeInfoList, nodeInfo)
			}
		}
	}
}
```

## 总结：

1. Cache缓存了Pod和Node信息，并且Node信息聚合了运行在该Node上所有Pod的资源量和镜像信息；Node有虚实之分，已删除的Node，Cache不会立刻删除它，而是继续维护一个虚的Node，直到Node上的Pod清零后才会被删除；但是nodeTree中维护的是实际的Node，调度使用nodeTree就可以避免将Pod调度到虚Node上；
2. kube-scheduler利用client-go监控(watch)Pod和Node状态，当有事件发生时调用Cache的AddPod，RemovePod，UpdatePod，AddNode，RemoveNode，UpdateNode更新Cache中Pod和Node的状态，这样kube-scheduler开始新一轮调度的时候可以获得最新的状态；
3. kube-scheduler每一轮调度都会调用UpdateSnapshot更新本地(局部变量)的Node状态，因为Cache中的Node按照最近更新排序，只需要将Cache中Node.Generation大于kube-scheduler本地的快照generation的Node更新到snapshot中即可，这样可以避免大量不必要的拷贝；
4. kube-scheduler找到合适的Node调度Pod后，需要调用Cache.AssumePod假定Pod已调度，然后启动协程异步Bind Pod到Node上，当Pod完成Bind后，调用Cache.FinishBinding通知Cache；
5. kube-scheudler调用Cache.AssumePod后续的所有造作一旦有错误就会调用Cache.ForgetPod删除假定的Pod，释放资源；
6. 完成Bind的Pod默认超时为30秒，Cache有一个协程定时(1秒)清理超时的Bind超时的Pod，如果超时依然没有收到Pod确认消息(调用AddPod)，则将删除超时的Pod，进而释放出Cache.AssumePod占用的资源;
7. Cache的核心功能就是统计Node的调度状态(比如累加Pod的资源量、统计镜像)，然后以镜像的形式输出给kube-scheduler，kube-scheduler从调度队列(SchedulingQueue)中取出等待调度的Pod，根据镜像计算最合适的Node；

此时再来看看源码中关于Pod状态机的注释就非常容易理解了：

```
// State Machine of a pod's events in scheduler's cache:
//
//
//   +-------------------------------------------+  +----+
//   |                            Add            |  |    |
//   |                                           |  |    | Update
//   +      Assume                Add            v  v    |
//Initial +--------> Assumed +------------+---> Added <--+
//   ^                +   +               |       +
//   |                |   |               |       |
//   |                |   |           Add |       | Remove
//   |                |   |               |       |
//   |                |   |               +       |
//   +----------------+   +-----------> Expired   +----> Deleted
//         Forget             Expire
//
```

上面总结中描述了kube-scheduler大致调度一个Pod的流程，其实kube-scheduler调度一个Pod的流程非常复杂，此处为了方便理解Cache在kube-scheduler中的位置和作用，剧透了部分内容。笔者会在后续文章中详细解析kube-scheduler调度Pod的详细流程。

