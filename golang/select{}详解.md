### 一、介绍
golang 中的 select 是用来监听和 channel 有关的 IO 操作，当 IO 操作发生时，触发相应的动作。select 只能应用于 channel 的操作，既可以用于 channel 的数据接收，也可以用于 channel 的数据发送。如果 select 的多个分支都满足条件，则会随机的选取其中一个满足条件的分支执行。

golang中的```select语句格式```如下：(类似switch的写法，但case后面是不带判断条件的，而是一个信道的操作。)

```
select {
case <-ch1:
// 如果从 ch1 信道成功接收数据，则执行该分支代码
case ch2 <- 1:
// 如果成功向 ch2 信道成功发送数据，则执行该分支代码
default:
// 如果上面都没有成功，则进入 default 分支处理流程
}
```

### 二、 相关知识点及示例
#### 1. select语句只能用于信道的读写操作
```
package main

import "fmt"

func main() {
    size := 10
    ch := make(chan int, size)
    for i := 0; i < size; i++ {
        ch <- 1
    }

    ch3 := make(chan int, 1)
    select {
    case 3 == 3:  //IDE中会提示 `The select case must have a receive operation, a send operation, an assignment, or a short var declaration`
        fmt.Println("equal")
    case v := <-ch:
        fmt.Print(v)
    case ch3 <- 10:
        fmt.Print("write")
    default:
        fmt.Println("none")
    }
}
```
#### 2. select中的case语句是随机执行的
select中的case条件(非阻塞)是并发执行的，select会选择先操作成功的那个case条件去执行，如果多个同时返回，则随机选择一个执行，此时将无法保证执行顺序。对于阻塞的case语句会直到其中有信道可以操作，如果有多个信道可操作，会随机选择其中一个 case 执行
```go
package main

import "fmt"

func main() {
	size := 10
	ch := make(chan int, size)
	for i := 0; i < size; i++ {
		ch <- 1
	}

	ch3 := make(chan int, 1)

	select {
	case v := <-ch:
		fmt.Print(v)
	case ch3 <- 10:
		fmt.Print("write")
	default:
		fmt.Println("none")
	}
}
```

#### 3. 对于case条件语句中，如果存在信道值为nil的读写操作，则该分支将被忽略，可以理解为从select语句中删除了这个case语句
```go
package main

import "fmt"

func main() {
	var ch chan int
	//ch = make(chan int)
	go func(c chan int) {
		c <- 100
	}(ch)

	select {
	case <-ch:
		fmt.Print("ok")
	}
}
```
#### 4. 超时用法
如果有超时条件语句，判断逻辑为 如果在这个时间段内一直没有满足条件的case,则执行这个超时case。如果此段时间内出现了可操作的case,则直接执行这个case。一般用超时语句代替了default语句
```go
package main

import (
	"fmt"
	"time"
)

func main() {
	ch := make(chan int)
	go func(c chan int) {
		// 修改时间后,再查看执行结果 调小至2s一下则会是1
		time.Sleep(time.Second * 3)
		ch <- 1
	}(ch)

	select {
	case v := <-ch:
		fmt.Print(v)
	case <-time.After(2 * time.Second): // 等待 2s
		fmt.Println("no case ok")
	}

	time.Sleep(time.Second * 10)
}
```
#### 5. 对于空的select{}，会引起死锁
```go
package main

import "fmt"

func main() {
	num := 10
	for i := 0; i < num; i++ {
		fmt.Println(i)
	}
	select {} //引发错误如下：fatal error: all goroutines are asleep - deadlock!
}
```

#### 6. 对于for中的select{}, 也有可能会引起cpu占用过高的问题
```go
package main
import (
	"runtime"
	"time"
)
func main() {
	quit := make(chan bool)
	for i := 0; i != runtime.NumCPU(); i++ {
		go func() {
			for {
				select {
				case <-quit:
					break
				default:
				}
			}
		}()
	}
	time.Sleep(time.Second * 15)
	for i := 0; i != runtime.NumCPU(); i++ {
		quit <- true
	}
}
```
一般来说，我们用select监听各个case的IO事件，每个case都是阻塞的。上面的例子中，我们希望select在获取到quit通道里面的数据时立即退出循环，但由于他在for{}里面，在第一次读取quit后，仅仅退出了select{}，并未退出for，所以下次还会继续执行select{}逻辑，此时永远是执行default，直到quit通道里读到数据，否则会一直在一个死循环中运行，即使放到一个goroutine里运行，也是会占满所有的CPU。

解决方法就是把default去掉即可，这样select就会一直阻塞在quit通道的IO上， 当quit有数据时，就能够随时响应通道中的信息。可参考：https://blog.haohtml.com/archives/20017