;; A real component-model transport fixture for fcp:connector@1.0.0.
;;
;; fcp-dispatch(method: string, request: list<u8>) -> list<u8>
;;
;; Ordinary calls return four bytes:
;;   [call_count, first_method_byte, first_request_byte, prior_post_return_count]
;; Counts are truncated to one byte. Empty strings/lists contribute zero.
;; The counter belongs to the retained core instance, not the host harness.
;;
;; Special methods exercise distinct transport outcomes:
;;   error       returns canonical CBOR {"error": "fixture"} without trapping
;;   large       returns 65,537 bytes of 0x5a from a valid memory range
;;   trap        traps in the dispatch body
;;   bad_return  returns an out-of-bounds list descriptor
;;   post_trap   returns normally, then traps in canonical post-return
;;   spin        loops forever until runtime fuel or timeout interrupts it
;;
;; Post-return overwrites the returned bytes, clears the pending-call guard,
;; and releases all bump allocations. Repeated successful calls prove that
;; the runtime lifts owned bytes before cleanup and performs cleanup exactly
;; once. This fixture has no WASI or other host imports.
(component
  (core module $guest
    (memory (export "memory") 4 4)
    (global $heap (mut i32) (i32.const 4096))
    (global $calls (mut i32) (i32.const 0))
    (global $cleanups (mut i32) (i32.const 0))
    (global $pending (mut i32) (i32.const 0))
    (global $post_trap (mut i32) (i32.const 0))
    (global $response_ptr (mut i32) (i32.const 256))
    (global $response_len (mut i32) (i32.const 4))

    (data (i32.const 64) "trap")
    (data (i32.const 80) "bad_return")
    (data (i32.const 96) "post_trap")
    (data (i32.const 112) "large")
    (data (i32.const 128) "error")
    (data (i32.const 144) "spin")
    (data (i32.const 160) "\a1\65error\67fixture")

    (func $realloc (export "realloc")
      (param $old_ptr i32) (param $old_size i32)
      (param $align i32) (param $new_size i32) (result i32)
      (local $ptr i32) (local $end i32) (local $copy_size i32)
      (if (i32.eqz (local.get $new_size))
        (then (return (i32.const 0))))
      (local.set $ptr
        (i32.and
          (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1)))
          (i32.sub (i32.const 0) (local.get $align))))
      (local.set $end (i32.add (local.get $ptr) (local.get $new_size)))
      (if
        (i32.or
          (i32.lt_u (local.get $end) (local.get $ptr))
          (i32.gt_u (local.get $end) (i32.const 262144)))
        (then unreachable))
      (global.set $heap (local.get $end))
      (local.set $copy_size
        (select (local.get $old_size) (local.get $new_size)
          (i32.lt_u (local.get $old_size) (local.get $new_size))))
      (if (local.get $copy_size)
        (then
          (memory.copy
            (local.get $ptr) (local.get $old_ptr) (local.get $copy_size))))
      (local.get $ptr))

    (func $equals
      (param $actual i32) (param $actual_len i32)
      (param $expected i32) (param $expected_len i32) (result i32)
      (local $index i32)
      (if (i32.ne (local.get $actual_len) (local.get $expected_len))
        (then (return (i32.const 0))))
      (block $done
        (loop $bytes
          (br_if $done (i32.eq (local.get $index) (local.get $actual_len)))
          (if
            (i32.ne
              (i32.load8_u (i32.add (local.get $actual) (local.get $index)))
              (i32.load8_u (i32.add (local.get $expected) (local.get $index))))
            (then (return (i32.const 0))))
          (local.set $index (i32.add (local.get $index) (i32.const 1)))
          (br $bytes)))
      (i32.const 1))

    (func $dispatch (export "dispatch")
      (param $method i32) (param $method_len i32)
      (param $request i32) (param $request_len i32) (result i32)
      (if (global.get $pending) (then unreachable))
      (global.set $pending (i32.const 1))
      (global.set $calls (i32.add (global.get $calls) (i32.const 1)))
      (if
        (call $equals (local.get $method) (local.get $method_len)
          (i32.const 144) (i32.const 4))
        (then (loop $spin (br $spin))))
      (if
        (call $equals (local.get $method) (local.get $method_len)
          (i32.const 64) (i32.const 4))
        (then unreachable))
      (if
        (call $equals (local.get $method) (local.get $method_len)
          (i32.const 80) (i32.const 10))
        (then
          (i32.store (i32.const 32) (i32.const 262144))
          (i32.store (i32.const 36) (i32.const 4))
          (return (i32.const 32))))
      (global.set $post_trap
        (call $equals (local.get $method) (local.get $method_len)
          (i32.const 96) (i32.const 9)))
      (global.set $response_ptr (i32.const 256))
      (global.set $response_len (i32.const 4))
      (if
        (call $equals (local.get $method) (local.get $method_len)
          (i32.const 128) (i32.const 5))
        (then
          (global.set $response_len (i32.const 15))
          (memory.copy (i32.const 256) (i32.const 160) (i32.const 15)))
        (else
          (if
            (call $equals (local.get $method) (local.get $method_len)
              (i32.const 112) (i32.const 5))
            (then
              (global.set $response_ptr (i32.const 512))
              (global.set $response_len (i32.const 65537))
              (memory.fill (i32.const 512) (i32.const 90) (i32.const 65537)))
            (else
              (i32.store8 (i32.const 256) (global.get $calls))
              (i32.store8 (i32.const 257)
                (if (result i32) (local.get $method_len)
                  (then (i32.load8_u (local.get $method)))
                  (else (i32.const 0))))
              (i32.store8 (i32.const 258)
                (if (result i32) (local.get $request_len)
                  (then (i32.load8_u (local.get $request)))
                  (else (i32.const 0))))
              (i32.store8 (i32.const 259) (global.get $cleanups))))))
      (i32.store (i32.const 32) (global.get $response_ptr))
      (i32.store (i32.const 36) (global.get $response_len))
      (i32.const 32))

    (func $post_return (export "post-return") (param $result i32)
      (if (i32.ne (local.get $result) (i32.const 32)) (then unreachable))
      (if (global.get $post_trap) (then unreachable))
      (if (i32.eqz (global.get $pending)) (then unreachable))
      (memory.fill
        (global.get $response_ptr) (i32.const 238) (global.get $response_len))
      (global.set $cleanups (i32.add (global.get $cleanups) (i32.const 1)))
      (global.set $pending (i32.const 0))
      (global.set $heap (i32.const 4096))))

  (core instance $instance (instantiate $guest))
  (func (export "fcp-dispatch")
    (param "method" string) (param "request" (list u8)) (result (list u8))
    (canon lift (core func $instance "dispatch")
      (memory $instance "memory")
      (realloc (func $instance "realloc"))
      (post-return (func $instance "post-return")))))
