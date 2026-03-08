;; Lattice Spectra Supply Chain Contract

;; ============================================================
;; CONSTANTS
;; ============================================================

(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED        (err u100))
(define-constant ERR-ALREADY-REGISTERED  (err u101))
(define-constant ERR-NOT-REGISTERED      (err u102))
(define-constant ERR-INVALID-SCORE       (err u103))
(define-constant ERR-INSUFFICIENT-STAKE  (err u104))
(define-constant ERR-SHIPMENT-NOT-FOUND  (err u105))
(define-constant ERR-INVALID-TRANSITION  (err u106))
(define-constant ERR-SELF-ATTEST         (err u107))

;; Trust score bounds (0-100)
(define-constant MIN-TRUST-SCORE u0)
(define-constant MAX-TRUST-SCORE u100)

;; Minimum stake required per trust-score unit (in microSTX)
(define-constant STAKE-PER-TRUST-UNIT u1000000) ;; 1 STX per trust point

;; Compliance threshold: participants below this are flagged
(define-constant COMPLIANCE-THRESHOLD u50)

;; ============================================================
;; DATA MAPS AND VARS
;; ============================================================

;; Global shipment counter
(define-data-var shipment-nonce uint u0)

;; Participant node in the supply chain lattice
(define-map participants
  { participant: principal }
  {
    trust-score:        uint,   ;; 0-100
    compliance-rating:  uint,   ;; 0-100, based on fulfilled obligations
    performance-score:  uint,   ;; 0-100, on-time delivery, quality etc.
    risk-score:         uint,   ;; 0-100, lower is safer
    env-impact-score:   uint,   ;; 0-100, lower is greener
    staked-amount:      uint,   ;; microSTX currently staked
    is-compliant:       bool,   ;; true when compliance-rating >= threshold
    registered-at:      uint    ;; block height of registration
  }
)

;; Shipment tracking: each shipment moves through defined states
;; States: 0=created, 1=in-transit, 2=at-checkpoint, 3=delivered, 4=disputed
(define-map shipments
  { shipment-id: uint }
  {
    origin:       principal,
    destination:  principal,
    custodian:    principal,   ;; current responsible party
    state:        uint,
    created-at:   uint,
    updated-at:   uint,
    metadata-hash: (buff 32)   ;; commitment hash of off-chain shipment data
  }
)

;; Trust attestations between participants (directed graph edges)
(define-map trust-attestations
  { attester: principal, subject: principal }
  {
    score:       uint,  ;; attested trust score 0-100
    attested-at: uint
  }
)

;; Compliance events logged per participant
(define-map compliance-events
  { participant: principal, event-id: uint }
  {
    event-type:  (string-ascii 32),  ;; e.g. "PASSED", "FAILED", "WARNING"
    recorded-at: uint,
    recorder:    principal
  }
)

;; Compliance event counter per participant
(define-map compliance-event-nonce
  { participant: principal }
  { nonce: uint }
)

;; ============================================================
;; PRIVATE HELPERS
;; ============================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (participant-exists (p principal))
  (is-some (map-get? participants { participant: p }))
)

(define-private (clamp-score (score uint))
  (if (> score MAX-TRUST-SCORE)
    MAX-TRUST-SCORE
    score)
)

;; Compute required stake from trust score
(define-private (required-stake (trust-score uint))
  (* trust-score STAKE-PER-TRUST-UNIT)
)

;; Recompute compliance flag based on current compliance-rating
(define-private (compute-compliance (rating uint))
  (>= rating COMPLIANCE-THRESHOLD)
)

;; ============================================================
;; PARTICIPANT MANAGEMENT
;; ============================================================

;; Register a new participant and stake tokens proportional to trust score
(define-public (register-participant
    (initial-trust-score uint)
    (initial-performance  uint)
    (initial-risk         uint)
    (initial-env-impact   uint))
  (let (
    (caller tx-sender)
    (ts  (clamp-score initial-trust-score))
    (perf (clamp-score initial-performance))
    (risk (clamp-score initial-risk))
    (env  (clamp-score initial-env-impact))
    (stake-needed (required-stake ts))
  )
    (asserts! (not (participant-exists caller)) ERR-ALREADY-REGISTERED)
    ;; Transfer stake to contract
    (try! (stx-transfer? stake-needed caller (as-contract tx-sender)))
    (map-set participants { participant: caller }
      {
        trust-score:       ts,
        compliance-rating: u75,   ;; default neutral compliance
        performance-score: perf,
        risk-score:        risk,
        env-impact-score:  env,
        staked-amount:     stake-needed,
        is-compliant:      (compute-compliance u75),
        registered-at:     block-height
      }
    )
    (ok true)
  )
)

;; Update own performance and environmental scores
(define-public (update-self-metrics
    (new-performance uint)
    (new-env-impact  uint))
  (let (
    (caller tx-sender)
    (record (unwrap! (map-get? participants { participant: caller }) ERR-NOT-REGISTERED))
  )
    (map-set participants { participant: caller }
      (merge record {
        performance-score: (clamp-score new-performance),
        env-impact-score:  (clamp-score new-env-impact)
      })
    )
    (ok true)
  )
)

;; Owner can adjust a participant's trust and risk scores (governance action)
(define-public (governance-update-scores
    (target     principal)
    (new-trust  uint)
    (new-risk   uint))
  (let (
    (record (unwrap! (map-get? participants { participant: target }) ERR-NOT-REGISTERED))
    (ts  (clamp-score new-trust))
    (risk (clamp-score new-risk))
    (current-stake (get staked-amount record))
    (required      (required-stake ts))
  )
    (asserts! (is-contract-owner) ERR-UNAUTHORIZED)
    ;; If new required stake is higher, participant must top up separately;
    ;; governance only updates scores here.
    (map-set participants { participant: target }
      (merge record {
        trust-score: ts,
        risk-score:  risk
      })
    )
    (ok true)
  )
)

;; ============================================================
;; STAKING
;; ============================================================

;; Participant tops up stake (e.g. after trust score increase)
(define-public (top-up-stake (amount uint))
  (let (
    (caller tx-sender)
    (record (unwrap! (map-get? participants { participant: caller }) ERR-NOT-REGISTERED))
    (new-total (+ (get staked-amount record) amount))
  )
    (try! (stx-transfer? amount caller (as-contract tx-sender)))
    (map-set participants { participant: caller }
      (merge record { staked-amount: new-total })
    )
    (ok new-total)
  )
)

;; Participant withdraws excess stake above what their trust score requires
(define-public (withdraw-excess-stake)
  (let (
    (caller tx-sender)
    (record (unwrap! (map-get? participants { participant: caller }) ERR-NOT-REGISTERED))
    (current  (get staked-amount record))
    (required (required-stake (get trust-score record)))
  )
    (asserts! (> current required) ERR-INSUFFICIENT-STAKE)
    (let ((excess (- current required)))
      (try! (as-contract (stx-transfer? excess tx-sender caller)))
      (map-set participants { participant: caller }
        (merge record { staked-amount: required })
      )
      (ok excess)
    )
  )
)

;; ============================================================
;; TRUST ATTESTATIONS
;; ============================================================

;; A registered participant attests to another participant's trust level.
;; The subject's trust-score is updated as a simple average of
;; their current score and the attested score.
(define-public (attest-trust (subject principal) (attested-score uint))
  (let (
    (caller tx-sender)
    (score  (clamp-score attested-score))
    (subject-record (unwrap! (map-get? participants { participant: subject }) ERR-NOT-REGISTERED))
  )
    (asserts! (participant-exists caller) ERR-NOT-REGISTERED)
    (asserts! (not (is-eq caller subject))  ERR-SELF-ATTEST)
    ;; Store directed attestation
    (map-set trust-attestations
      { attester: caller, subject: subject }
      { score: score, attested-at: block-height }
    )
    ;; Update subject trust score: simple moving average with current value
    (let ((new-trust (/ (+ (get trust-score subject-record) score) u2)))
      (map-set participants { participant: subject }
        (merge subject-record { trust-score: new-trust })
      )
    )
    (ok true)
  )
)

;; ============================================================
;; COMPLIANCE EVENTS
;; ============================================================

;; Owner records a compliance event for a participant.
;; "PASSED" increases compliance-rating, "FAILED" decreases it.
(define-public (record-compliance-event
    (target     principal)
    (event-type (string-ascii 32)))
  (let (
    (record (unwrap! (map-get? participants { participant: target }) ERR-NOT-REGISTERED))
    (nonce-entry (default-to { nonce: u0 }
                   (map-get? compliance-event-nonce { participant: target })))
    (event-id (get nonce nonce-entry))
    (current-rating (get compliance-rating record))
    ;; Adaptive adjustment: PASSED +5, FAILED -10, WARNING -3
    (new-rating
      (if (is-eq event-type "PASSED")
        (clamp-score (+ current-rating u5))
        (if (is-eq event-type "FAILED")
          (if (>= current-rating u10) (- current-rating u10) u0)
          (if (is-eq event-type "WARNING")
            (if (>= current-rating u3) (- current-rating u3) u0)
            current-rating
          )
        )
      )
    )
  )
    (asserts! (is-contract-owner) ERR-UNAUTHORIZED)
    (map-set compliance-events
      { participant: target, event-id: event-id }
      { event-type: event-type, recorded-at: block-height, recorder: tx-sender }
    )
    (map-set compliance-event-nonce
      { participant: target }
      { nonce: (+ event-id u1) }
    )
    (map-set participants { participant: target }
      (merge record {
        compliance-rating: new-rating,
        is-compliant:      (compute-compliance new-rating)
      })
    )
    (ok new-rating)
  )
)

;; ============================================================
;; SHIPMENT LIFECYCLE
;; ============================================================

;; Create a new shipment between two registered participants.
;; metadata-hash is a 32-byte commitment to off-chain shipment documents.
(define-public (create-shipment
    (destination   principal)
    (metadata-hash (buff 32)))
  (let (
    (caller  tx-sender)
    (ship-id (var-get shipment-nonce))
  )
    (asserts! (participant-exists caller)      ERR-NOT-REGISTERED)
    (asserts! (participant-exists destination) ERR-NOT-REGISTERED)
    (map-set shipments { shipment-id: ship-id }
      {
        origin:        caller,
        destination:   destination,
        custodian:     caller,
        state:         u0,        ;; created
        created-at:    block-height,
        updated-at:    block-height,
        metadata-hash: metadata-hash
      }
    )
    (var-set shipment-nonce (+ ship-id u1))
    (ok ship-id)
  )
)

;; Advance shipment state. Valid transitions:
;;   0 -> 1 (created -> in-transit)
;;   1 -> 2 (in-transit -> at-checkpoint)
;;   2 -> 1 (checkpoint -> in-transit again)
;;   1 -> 3 (in-transit -> delivered)
;;   any -> 4 (raise dispute, owner only)
(define-public (advance-shipment-state
    (shipment-id uint)
    (new-state   uint))
  (let (
    (record (unwrap! (map-get? shipments { shipment-id: shipment-id }) ERR-SHIPMENT-NOT-FOUND))
    (current-state (get state record))
    (caller tx-sender)
  )
    ;; Dispute transition: owner only
    (if (is-eq new-state u4)
      (asserts! (is-contract-owner) ERR-UNAUTHORIZED)
      ;; Normal transitions: custodian only
      (asserts! (is-eq caller (get custodian record)) ERR-UNAUTHORIZED)
    )
    ;; Validate transition
    (asserts!
      (or
        (and (is-eq current-state u0) (is-eq new-state u1))
        (and (is-eq current-state u1) (is-eq new-state u2))
        (and (is-eq current-state u2) (is-eq new-state u1))
        (and (is-eq current-state u1) (is-eq new-state u3))
        (is-eq new-state u4)
      )
      ERR-INVALID-TRANSITION
    )
    (map-set shipments { shipment-id: shipment-id }
      (merge record {
        state:      new-state,
        updated-at: block-height
      })
    )
    (ok new-state)
  )
)

;; Transfer custodianship of an in-transit shipment to another participant
(define-public (transfer-custodian
    (shipment-id  uint)
    (new-custodian principal))
  (let (
    (record (unwrap! (map-get? shipments { shipment-id: shipment-id }) ERR-SHIPMENT-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get custodian record)) ERR-UNAUTHORIZED)
    (asserts! (participant-exists new-custodian)        ERR-NOT-REGISTERED)
    (asserts! (is-eq (get state record) u1)             ERR-INVALID-TRANSITION)
    (map-set shipments { shipment-id: shipment-id }
      (merge record { custodian: new-custodian, updated-at: block-height })
    )
    (ok true)
  )
)

;; ============================================================
;; READ-ONLY QUERIES
;; ============================================================

(define-read-only (get-participant (p principal))
  (map-get? participants { participant: p })
)

(define-read-only (get-shipment (shipment-id uint))
  (map-get? shipments { shipment-id: shipment-id })
)

(define-read-only (get-attestation (attester principal) (subject principal))
  (map-get? trust-attestations { attester: attester, subject: subject })
)

(define-read-only (get-compliance-event (participant principal) (event-id uint))
  (map-get? compliance-events { participant: participant, event-id: event-id })
)

(define-read-only (get-total-shipments)
  (var-get shipment-nonce)
)

(define-read-only (is-participant-compliant (p principal))
  (match (map-get? participants { participant: p })
    record (ok (get is-compliant record))
    ERR-NOT-REGISTERED
  )
)

;; Compute spectral risk score: weighted combination of risk and compliance
;; Returns a value 0-100 where lower is healthier
(define-read-only (get-spectral-risk-score (p principal))
  (match (map-get? participants { participant: p })
    record
      (let (
        (risk        (get risk-score record))
        (compliance  (get compliance-rating record))
        ;; Invert compliance so low compliance increases risk signal
        (inv-compliance (- u100 compliance))
        ;; Weighted: 60% raw risk, 40% compliance signal
        (spectral (/ (+ (* risk u60) (* inv-compliance u40)) u100))
      )
        (ok spectral)
      )
    ERR-NOT-REGISTERED
  )
)
