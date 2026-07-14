module github.com/kzelealem/hookbound/integration/postgres

go 1.23.0

require (
	github.com/kzelealem/hookbound v0.0.0
	github.com/lib/pq v1.12.3
)

replace github.com/kzelealem/hookbound => ../..
