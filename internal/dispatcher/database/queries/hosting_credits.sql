-- name: ResetHostingCreditObservation :exec
-- Revocation ends a credit interval immediately, even if a matching credential
-- is enrolled again before the next maintenance pass. Earned history stays.
UPDATE allowance_hosting SET incarnation='',session_id='',fingerprint='',observed_at=0
WHERE executor_id=?;
