package memory

import (
	"container/heap"
	"debuglet/internal/executor/transport/rpc"
)

type item struct {
	index  int
	upload *rpc.Upload
}

type priorityQueue []*item

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	if pq[i].upload.StartTime == nil {
		return true
	}
	if pq[j].upload.StartTime == nil {
		return false
	}
	return pq[i].upload.StartTime.Before(*pq[j].upload.StartTime)
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *priorityQueue) Push(x any) {
	item := x.(*item)
	item.index = len(*pq)
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1
	old[n-1] = nil
	*pq = old[0 : n-1]
	return item
}

// TimedQueue abstracts the priority queue to allow for the removal of
// specific IDs in amortized O(1)
type TimedQueue struct {
	pq   *priorityQueue
	refs map[string]*item
}

func NewTimedQueue() *TimedQueue {
	pq := &priorityQueue{}
	heap.Init(pq)
	return &TimedQueue{pq: pq, refs: make(map[string]*item)}
}

func (tq *TimedQueue) Push(x rpc.Upload) {
	item := item{upload: &x}
	heap.Push(tq.pq, &item)
	tq.refs[x.DebugletID] = &item
}

func (tq *TimedQueue) Peek(ind int) *rpc.Upload {
	return (*tq.pq)[ind].upload
}

func (tq *TimedQueue) Pop() *rpc.Upload {
	u := heap.Pop(tq.pq).(*item).upload
	delete(tq.refs, u.DebugletID)
	return u
}

func (tq *TimedQueue) Len() int {
	return tq.pq.Len()
}

func (tq *TimedQueue) Remove(ID string) *rpc.Upload {
	it, exists := tq.refs[ID]
	if !exists {
		return nil
	}
	return heap.Remove(tq.pq, it.index).(*item).upload
}
