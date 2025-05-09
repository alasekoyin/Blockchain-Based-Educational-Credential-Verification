;; Verification Access Contract
;; This contract controls third-party credential checks

(define-data-var admin principal tx-sender)

;; Map to store verifier permissions
(define-map verifiers
  { verifier-id: principal }
  {
    name: (string-ascii 100),
    approved: bool,
    approval-date: uint,
    access-level: uint  ;; 1: basic, 2: detailed, 3: full
  }
)

;; Map to store student consent for verifiers
(define-map student-consents
  {
    student-id: (string-ascii 64),
    verifier-id: principal
  }
  {
    granted: bool,
    grant-date: uint,
    expiration-date: (optional uint)
  }
)

;; Function to register a new verifier (admin only)
(define-public (register-verifier (verifier-id principal) (name (string-ascii 100)) (access-level uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (asserts! (and (>= access-level u1) (<= access-level u3)) (err u400))
    (ok (map-set verifiers
      { verifier-id: verifier-id }
      {
        name: name,
        approved: true,
        approval-date: block-height,
        access-level: access-level
      }
    ))
  )
)

;; Function for students to grant consent to a verifier
(define-public (grant-consent (student-id (string-ascii 64)) (verifier-id principal) (expiration-date (optional uint)))
  (begin
    ;; Check if verifier is approved
    (asserts! (default-to false (get approved (map-get? verifiers { verifier-id: verifier-id }))) (err u404))

    (ok (map-set student-consents
      {
        student-id: student-id,
        verifier-id: verifier-id
      }
      {
        granted: true,
        grant-date: block-height,
        expiration-date: expiration-date
      }
    ))
  )
)

;; Function for students to revoke consent
(define-public (revoke-consent (student-id (string-ascii 64)) (verifier-id principal))
  (begin
    (match (map-get? student-consents { student-id: student-id, verifier-id: verifier-id })
      consent (ok (map-set student-consents
        { student-id: student-id, verifier-id: verifier-id }
        (merge consent { granted: false })
      ))
      (err u404)
    )
  )
)

;; Function to check if a verifier has consent to access a student's credentials
(define-read-only (has-consent (student-id (string-ascii 64)) (verifier-id principal))
  (match (map-get? student-consents { student-id: student-id, verifier-id: verifier-id })
    consent (begin
      (and
        (get granted consent)
        (match (get expiration-date consent)
          expiry (< block-height expiry)
          true
        )
      )
    )
    false
  )
)

;; Function to get verifier access level
(define-read-only (get-access-level (verifier-id principal))
  (default-to u0 (get access-level (map-get? verifiers { verifier-id: verifier-id })))
)

;; Function to revoke verifier approval (admin only)
(define-public (revoke-verifier (verifier-id principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (match (map-get? verifiers { verifier-id: verifier-id })
      verifier (ok (map-set verifiers
        { verifier-id: verifier-id }
        (merge verifier { approved: false })
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
