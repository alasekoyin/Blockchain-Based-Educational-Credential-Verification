;; Institution Verification Contract
;; This contract validates legitimate educational entities

(define-data-var admin principal tx-sender)

;; Map to store verified institutions
(define-map verified-institutions
  { institution-id: (string-ascii 64) }
  {
    name: (string-ascii 100),
    website: (string-ascii 100),
    verified: bool,
    verification-date: uint
  }
)

;; Function to register a new institution (admin only)
(define-public (register-institution (institution-id (string-ascii 64)) (name (string-ascii 100)) (website (string-ascii 100)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-none (map-get? verified-institutions { institution-id: institution-id })) (err u100))
    (ok (map-set verified-institutions
      { institution-id: institution-id }
      {
        name: name,
        website: website,
        verified: true,
        verification-date: block-height
      }
    ))
  )
)

;; Function to check if an institution is verified
(define-read-only (is-institution-verified (institution-id (string-ascii 64)))
  (match (map-get? verified-institutions { institution-id: institution-id })
    institution (ok (get verified institution))
    (err u404)
  )
)

;; Function to update institution information (admin only)
(define-public (update-institution (institution-id (string-ascii 64)) (name (string-ascii 100)) (website (string-ascii 100)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (is-some (map-get? verified-institutions { institution-id: institution-id })) (err u404))
    (ok (map-set verified-institutions
      { institution-id: institution-id }
      {
        name: name,
        website: website,
        verified: true,
        verification-date: block-height
      }
    ))
  )
)

;; Function to revoke institution verification (admin only)
(define-public (revoke-institution (institution-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (match (map-get? verified-institutions { institution-id: institution-id })
      institution (ok (map-set verified-institutions
        { institution-id: institution-id }
        (merge institution { verified: false })
      ))
      (err u404)
    )
  )
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
