;; Student Identity Contract
;; This contract securely manages learner information

(define-data-var admin principal tx-sender)

;; Map to store student identities
(define-map students
  { student-id: (string-ascii 64) }
  {
    name: (string-ascii 100),
    hash: (buff 32),
    registered-by: principal,
    registration-date: uint
  }
)

;; Map to track institution permissions to register students
(define-map institution-permissions
  { institution-id: (string-ascii 64) }
  { can-register: bool }
)

;; Function to grant institution permission to register students (admin only)
(define-public (grant-institution-permission (institution-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (map-set institution-permissions
      { institution-id: institution-id }
      { can-register: true }
    ))
  )
)

;; Function to register a new student (institutions only)
(define-public (register-student (student-id (string-ascii 64)) (name (string-ascii 100)) (identity-hash (buff 32)) (institution-id (string-ascii 64)))
  (begin
    ;; Check if institution has permission
    (asserts! (default-to false (get can-register (map-get? institution-permissions { institution-id: institution-id }))) (err u403))
    ;; Check if student doesn't already exist
    (asserts! (is-none (map-get? students { student-id: student-id })) (err u100))

    (ok (map-set students
      { student-id: student-id }
      {
        name: name,
        hash: identity-hash,
        registered-by: tx-sender,
        registration-date: block-height
      }
    ))
  )
)

;; Function to verify a student exists
(define-read-only (verify-student (student-id (string-ascii 64)))
  (is-some (map-get? students { student-id: student-id }))
)

;; Function to get student details
(define-read-only (get-student-details (student-id (string-ascii 64)))
  (map-get? students { student-id: student-id })
)

;; Function to revoke institution permission (admin only)
(define-public (revoke-institution-permission (institution-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (map-set institution-permissions
      { institution-id: institution-id }
      { can-register: false }
    ))
  )
)

;; Function to transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (var-set admin new-admin))
  )
)
