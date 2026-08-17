package managedoutbound

import "sync"

type Source interface {
	Name() string
	Outbounds() (ready []any, skippedTags []string, err error)
}

var (
	mu      sync.Mutex
	sources []Source
)

func Register(s Source) {
	if s == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, existing := range sources {
		if existing.Name() == s.Name() {
			return
		}
	}
	sources = append(sources, s)
}

func All() []Source {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Source, len(sources))
	copy(out, sources)
	return out
}

func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	sources = nil
}
