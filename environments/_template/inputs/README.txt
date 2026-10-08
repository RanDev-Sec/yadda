SecOps exports go here, under any file name. yadda recognises each file by its columns and uses the newest of each kind.

  telemetry inventory      shared/queries/telemetry_inventory.yaral
  rule health              shared/queries/rule_health.yaral   (set the dashboard time range to the maximum)
  rule false positives     shared/queries/rule_fp_rate.yaral
  log types per rule       shared/queries/rule_logtypes.yaral
  host OS per log type     shared/queries/log_type_host_os.yaral
  product alerts           shared/queries/product_alerts.yaral

With SecOps API access in environment.env, "yadda run" runs these queries itself.
