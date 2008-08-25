# Over-verbose global constant; for messing around when we're not quite in the path.
$PACKETFU_RELATIVE_PATH_FROM_EXAMPLES = File.expand_path(File.dirname(__FILE__), File.join('..','..'))
$: << $PACKETFU_RELATIVE_PATH_FROM_EXAMPLES
$:.uniq

