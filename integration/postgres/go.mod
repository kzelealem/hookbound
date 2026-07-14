module github.com/hookbound/hookbound/integration/postgres

go 1.23.0

require (
	github.com/hookbound/hookbound v0.0.0
	github.com/lib/pq v1.10.9
)

replace github.com/hookbound/hookbound => ../..
