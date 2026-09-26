-- name: NextTeslaChainGeneration :one
SELECT CAST(COALESCE(MAX(generation), 0) + 1 AS INTEGER) FROM tesla_chains;

-- name: CreateTeslaChain :exec
INSERT INTO tesla_chains (
    generation,
    anchor,
    epoch_base,
    delay_ns,
    chain_length,
    created_at
) VALUES (?, ?, ?, ?, ?, ?);

-- name: ListTeslaChains :many
SELECT * FROM tesla_chains
ORDER BY generation;
