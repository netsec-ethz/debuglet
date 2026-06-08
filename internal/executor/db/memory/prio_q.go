package memory

import "debuglet/internal/executor/transport"

type TimedQueue []*transport.Upload

func (pq TimedQueue) Len() int { return len(pq) }

func (pq TimedQueue) Less(i, j int) bool {
	if pq[i].StartTime == nil {
		return true
	}
	if pq[j].StartTime == nil {
		return false
	}
	return pq[i].StartTime.Before(*pq[j].StartTime)
}

func (pq TimedQueue) Swap(i, j int) { pq[i], pq[j] = pq[j], pq[i] }

func (pq *TimedQueue) Push(x any) {
	item := x.(*transport.Upload)
	*pq = append(*pq, item)
}

func (pq *TimedQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	*pq = old[0 : n-1]
	return item
}
