#!/usr/bin/env bash
# Caller must enable errexit; callbacks run as simple commands in fixed order.
run_batches() {
  build_service
  build_app
  verify_service
  finish_app
}
