;; Course Completion Contract
;; This contract records academic achievements

(define-data-var admin principal tx-sender)

;; Map to store course completions
(define-map course-completions
  {
    student-id: (string-ascii 64),
    course-id: (string-ascii 64)
  }
  {
    institution-id: (string-ascii 64),
    completion-date: uint,
    grade: (string-ascii 10),
    verified: bool
  }
)

;; Map to track institution permissions
(define-map institution-permissions
  { institution-id: (string-ascii 64) }
  { can-record: bool }
)

;; Function to grant institution permission to record completions (admin only)
(define-public (grant-institution-permission (institution-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (ok (map-set institution-permissions
      { institution-id: institution-id }
      { can-record: true }
    ))
  )
)

;; Function to record a course completion (institutions only)
(define-public (record-completion
  (student-id (string-ascii 64))
  (course-id (string-ascii 64))
  (institution-id (string-ascii 64))
  (grade (string-ascii 10)))
  (begin
    ;; Check if institution has permission
    (asserts! (default-to false (get can-record (map-get? institution-permissions { institution-id: institution-id }))) (err u403))

    ;; Record the completion
    (ok (map-set course-completions
      {
        student-id: student-id,
        course-id: course-id
      }
      {
        institution-id: institution-id,
        completion-date: block-height,
        grade: grade,
        verified: true
      }
    ))
  )
)

;; Function to verify a course completion
(define-read-only (verify-completion (student-id (string-ascii 64)) (course-id (string-ascii 64)))
  (match (map-get? course-completions { student-id: student-id, course-id: course-id })
    completion (get verified completion)
    false
  )
)

;; Function to get completion details
(define-read-only (get-completion-details (student-id (string-ascii 64)) (course-id (string-ascii 64)))
  (map-get? course-completions { student-id: student-id, course-id: course-id })
)

;; Function to revoke a course completion (admin only)
(define-public (revoke-completion (student-id (string-ascii 64)) (course-id (string-ascii 64)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err u403))
    (match (map-get? course-completions { student-id: student-id, course-id: course-id })
      completion (ok (map-set course-completions
        { student-id: student-id, course-id: course-id }
        (merge completion { verified: false })
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
