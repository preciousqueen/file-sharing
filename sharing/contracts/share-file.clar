;; File Categories/Tags and Linking Extensions (Validated & Warning-Free)

;; Error constants
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_FILE_NOT_FOUND (err u101))
(define-constant ERR_INVALID_FILE_ID (err u108))
(define-constant ERR_TAG_NOT_FOUND (err u200))
(define-constant ERR_INVALID_TAG_NAME (err u202))
(define-constant ERR_LINK_NOT_FOUND (err u204))
(define-constant ERR_INVALID_LINK_TYPE (err u206))
(define-constant ERR_CANNOT_LINK_TO_SELF (err u207))
(define-constant ERR_LIST_FULL (err u208))
(define-constant ERR_EMPTY_TAG_LIST (err u209))
(define-constant ERR_EMPTY_LINK_LIST (err u210))

;; Data variables
(define-data-var timestamp-counter uint u1)

;; Core maps (minimal definitions for compatibility)
(define-map files { file-id: (string-ascii 64) } { owner: principal })
(define-map file-permissions { file-id: (string-ascii 64), user: principal } { access-level: uint })

;; Tag system maps
(define-map file-tags { file-id: (string-ascii 64) } { tags: (list 10 (string-ascii 32)) })
(define-map tag-files { tag-name: (string-ascii 32) } { file-list: (list 50 (string-ascii 64)) })

;; Link system maps
(define-map file-links 
  { source: (string-ascii 64), target: (string-ascii 64) }
  { link-type: uint, created-at: uint }
)
(define-map file-connections { file-id: (string-ascii 64) } { links: (list 20 (string-ascii 64)) })

;; Helper functions
(define-private (get-time) 
  (let ((t (var-get timestamp-counter))) 
    (var-set timestamp-counter (+ t u1)) t))

(define-private (valid-file-id? (id (string-ascii 64))) 
  (and (>= (len id) u1) (<= (len id) u64)))

(define-private (valid-tag? (tag (string-ascii 32))) 
  (and (>= (len tag) u1) (<= (len tag) u32)))

(define-private (valid-link-type? (type uint)) 
  (and (>= type u1) (<= type u5)))

(define-private (has-permission? (file-id (string-ascii 64)) (user principal) (level uint))
  (let ((file-data (map-get? files { file-id: file-id })))
    (if (is-some file-data)
      (let ((owner (get owner (unwrap-panic file-data)))
            (perm (map-get? file-permissions { file-id: file-id, user: user })))
        (or (is-eq owner user)
            (and (is-some perm) (>= (get access-level (unwrap-panic perm)) level))))
      false)))

;; Validation helpers for lists
(define-private (validate-tag-list (tags (list 10 (string-ascii 32))))
  (fold validate-single-tag tags true))

(define-private (validate-single-tag (tag (string-ascii 32)) (acc bool))
  (and acc (valid-tag? tag)))

(define-private (validate-file-id-list (file-ids (list 20 (string-ascii 64))))
  (fold validate-single-file-id file-ids true))

(define-private (validate-single-file-id (file-id (string-ascii 64)) (acc bool))
  (and acc (valid-file-id? file-id)))

;; Tag functions with proper validation
(define-public (add-tag (file-id (string-ascii 64)) (tag (string-ascii 32)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (valid-tag? tag) ERR_INVALID_TAG_NAME)
    (asserts! (is-some (map-get? files { file-id: file-id })) ERR_FILE_NOT_FOUND)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    ;; Add tag to file using concat
    (let ((current-tags (default-to (list) (get tags (map-get? file-tags { file-id: file-id })))))
      (map-set file-tags { file-id: file-id } 
        { tags: (unwrap! (as-max-len? (concat (list tag) current-tags) u10) ERR_LIST_FULL) }))
    
    ;; Add file to tag index
    (let ((current-files (default-to (list) (get file-list (map-get? tag-files { tag-name: tag })))))
      (map-set tag-files { tag-name: tag }
        { file-list: (unwrap! (as-max-len? (concat (list file-id) current-files) u50) ERR_LIST_FULL) }))
    
    (ok true)))

(define-public (set-file-tags (file-id (string-ascii 64)) (tags (list 10 (string-ascii 32))))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (is-some (map-get? files { file-id: file-id })) ERR_FILE_NOT_FOUND)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    (asserts! (> (len tags) u0) ERR_EMPTY_TAG_LIST)
    (asserts! (validate-tag-list tags) ERR_INVALID_TAG_NAME)
    
    (map-set file-tags { file-id: file-id } { tags: tags })
    (ok true)))

(define-public (remove-all-tags (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-delete file-tags { file-id: file-id })
    (ok true)))

;; Link functions with proper validation
(define-public (create-link 
  (source (string-ascii 64)) 
  (target (string-ascii 64)) 
  (link-type uint))
  (begin
    (asserts! (valid-file-id? source) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? target) ERR_INVALID_FILE_ID)
    (asserts! (valid-link-type? link-type) ERR_INVALID_LINK_TYPE)
    (asserts! (not (is-eq source target)) ERR_CANNOT_LINK_TO_SELF)
    (asserts! (is-some (map-get? files { file-id: source })) ERR_FILE_NOT_FOUND)
    (asserts! (is-some (map-get? files { file-id: target })) ERR_FILE_NOT_FOUND)
    (asserts! (has-permission? source tx-sender u3) ERR_NOT_AUTHORIZED)
    
    ;; Create the link record
    (map-set file-links { source: source, target: target }
      { link-type: link-type, created-at: (get-time) })
    
    ;; Update source file connections
    (let ((source-links (default-to (list) (get links (map-get? file-connections { file-id: source })))))
      (map-set file-connections { file-id: source } 
        { links: (unwrap! (as-max-len? (concat (list target) source-links) u20) ERR_LIST_FULL) }))
    
    ;; Update target file connections
    (let ((target-links (default-to (list) (get links (map-get? file-connections { file-id: target })))))
      (map-set file-connections { file-id: target } 
        { links: (unwrap! (as-max-len? (concat (list source) target-links) u20) ERR_LIST_FULL) }))
    
    (ok true)))

(define-public (set-file-links (file-id (string-ascii 64)) (links (list 20 (string-ascii 64))))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (is-some (map-get? files { file-id: file-id })) ERR_FILE_NOT_FOUND)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    (asserts! (> (len links) u0) ERR_EMPTY_LINK_LIST)
    (asserts! (validate-file-id-list links) ERR_INVALID_FILE_ID)
    
    (map-set file-connections { file-id: file-id } { links: links })
    (ok true)))

(define-public (remove-link (source (string-ascii 64)) (target (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? source) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? target) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? source tx-sender u3) ERR_NOT_AUTHORIZED)
    (asserts! (is-some (map-get? file-links { source: source, target: target })) ERR_LINK_NOT_FOUND)
    
    (map-delete file-links { source: source, target: target })
    (ok true)))

(define-public (clear-file-links (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-delete file-connections { file-id: file-id })
    (ok true)))

;; Read-only functions
(define-read-only (get-file-tags (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (ok (default-to (list) (get tags (map-get? file-tags { file-id: file-id }))))))

(define-read-only (get-files-by-tag (tag (string-ascii 32)))
  (begin
    (asserts! (valid-tag? tag) ERR_INVALID_TAG_NAME)
    (ok (default-to (list) (get file-list (map-get? tag-files { tag-name: tag }))))))

(define-read-only (get-file-links (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (ok (default-to (list) (get links (map-get? file-connections { file-id: file-id }))))))

(define-read-only (get-link-info (source (string-ascii 64)) (target (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? source) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? target) ERR_INVALID_FILE_ID)
    (let ((link-data (map-get? file-links { source: source, target: target })))
      (if (is-some link-data)
        (ok (unwrap-panic link-data))
        ERR_LINK_NOT_FOUND))))

(define-read-only (get-link-type-name (type uint))
  (if (is-eq type u1) (ok "reference")
    (if (is-eq type u2) (ok "dependency") 
      (if (is-eq type u3) (ok "version")
        (if (is-eq type u4) (ok "related")
          (if (is-eq type u5) (ok "parent-child")
            ERR_INVALID_LINK_TYPE))))))

(define-read-only (get-file-summary (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (let ((tags (unwrap-panic (get-file-tags file-id)))
          (links (unwrap-panic (get-file-links file-id))))
      (ok { 
        tags: tags, 
        connections: links, 
        tag-count: (len tags), 
        link-count: (len links) 
      }))))

;; Search and utility functions
(define-read-only (has-tag? (file-id (string-ascii 64)) (tag (string-ascii 32)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (valid-tag? tag) ERR_INVALID_TAG_NAME)
    (let ((file-tags-list (unwrap-panic (get-file-tags file-id))))
      (ok (is-some (index-of file-tags-list tag))))))

(define-read-only (has-link? (source (string-ascii 64)) (target (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? source) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? target) ERR_INVALID_FILE_ID)
    (ok (is-some (map-get? file-links { source: source, target: target })))))

(define-read-only (count-file-tags (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (let ((tags (unwrap-panic (get-file-tags file-id))))
      (ok (len tags)))))

(define-read-only (count-file-links (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (let ((links (unwrap-panic (get-file-links file-id))))
      (ok (len links)))))

;; Validated batch operations
(define-public (quick-tag-file (file-id (string-ascii 64)) (tag1 (string-ascii 32)) (tag2 (string-ascii 32)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (valid-tag? tag1) ERR_INVALID_TAG_NAME)
    (asserts! (valid-tag? tag2) ERR_INVALID_TAG_NAME)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-set file-tags { file-id: file-id } { tags: (list tag1 tag2) })
    (ok true)))

(define-public (quick-link-files (file1 (string-ascii 64)) (file2 (string-ascii 64)) (file3 (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file1) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? file2) ERR_INVALID_FILE_ID)
    (asserts! (valid-file-id? file3) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? file1 tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-set file-connections { file-id: file1 } { links: (list file2 file3) })
    (ok true)))

;; Predefined validated tag sets
(define-public (tag-as-document (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-set file-tags { file-id: file-id } { tags: (list "document" "text" "office") })
    (ok true)))

(define-public (tag-as-media (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (asserts! (has-permission? file-id tx-sender u3) ERR_NOT_AUTHORIZED)
    
    (map-set file-tags { file-id: file-id } { tags: (list "media" "visual" "content") })
    (ok true)))

;; Reference data
(define-read-only (get-common-tags)
  (ok (list "document" "image" "video" "audio" "archive" "text" "media" "office" "data" "backup")))

(define-read-only (get-link-types)
  (ok (list u1 u2 u3 u4 u5)))

;; Simple search by single tag
(define-read-only (search-by-tag (tag (string-ascii 32)))
  (get-files-by-tag tag))

;; Check if file has any tags
(define-read-only (has-any-tags? (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (let ((tag-count (unwrap-panic (count-file-tags file-id))))
      (ok (> tag-count u0)))))

;; Check if file has any links
(define-read-only (has-any-links? (file-id (string-ascii 64)))
  (begin
    (asserts! (valid-file-id? file-id) ERR_INVALID_FILE_ID)
    (let ((link-count (unwrap-panic (count-file-links file-id))))
      (ok (> link-count u0)))))