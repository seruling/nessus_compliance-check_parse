<?php
$output = "<!DOCTYPE html>
	<html>
	<head>
	<style>
	body {
		font-family:'Calibri (Body)';
	}
	table, th, td {
	    border: 1px solid black;
	    border-collapse: collapse;
	    font-size:11pt;
	}
	th {
		color: #fff;
		background-color: #aaa;
		padding-left: 5px;
		padding-right: 5px;
	}
	td {
		padding-left: 5px;
		padding-right: 5px;
	}
	.critical {
		background-color: rgb(192,0,0);
	}
	.high {
		background-color: rgb(255,0,0);
	}
	.medium {
		background-color: rgb(255,192,0);
	}
	.low {
		background-color: rgb(146,208,80);
	}
	.total {
		background-color: rgb(0,176,240);
	}
	.th_head {
		color: #fff;
	}
	.bg-grey {
		background-color: #aaa;
	}
	.text-white {
		color: #fff;
		font-weight: bold;
	}
	.text-center {
		text-align: center;
	}
	.text-severity {
		color: rgb(79,98,40);
	}
	.text-host {
		color: rgb(31,73,125);
	}
	</style>
	</head>
	<body>
";
$files = array();
$dir = opendir('.');
function cleanup_text($string) {
	$string = str_replace("\n", "", $string);
	$string = str_replace("\r", "", $string);
	return $string;
}
function cleanup_filename($string) {
	$string = str_replace("\\", "", $string);
	$string = str_replace("/", "", $string);
	$string = str_replace("|", "", $string);
	$string = str_replace("*", "", $string);
	$string = str_replace("!", "", $string);
	$string = str_replace("?", "", $string);
	$string = str_replace("<", "", $string);
	$string = str_replace(">", "", $string);
	$string = str_replace("\"", "", $string);
	$string = str_replace(":", "", $string);
	return $string;
}
while(false != ($file = readdir($dir))) {
		if (preg_match("/.nessus/", $file)) {
                $files[] = $file; 
        }   
}

$total_count = 1;
$all_issue_total = "";
$all_critical = 0;
$all_high = 0;
$all_medium = 0;
$all_low = 0;
$all_total = 0;
$check_main_output = "";
$check_total_passed = 0;
$check_total_failed = 0;
$check_total_warning = 0;
$check_total_perhost = "";
foreach($files as $file) {
	$issue_total ="";
	$fileloop_output = "";
	$reports=simplexml_load_file($file) or die("Error: Cannot create object");
	$count_host = 0;
	foreach($reports->Report->ReportHost as $host) { 
		$count_host++;
	}
	$output_critical = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
	$output_high = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
	$output_medium = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
	$output_low = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";

	for ($i=0;$i<$count_host;$i++) {
		$host =  $reports->Report->ReportHost[$i]['name'];
		$count_issue = 0;
		$count_critical = 0;
		$count_high = 0;
		$count_medium = 0;
		$count_low = 0;
		$check_count_passed = 0;
		$check_count_failed = 0;
		$check_count_warning = 0;

		foreach($reports->Report->ReportHost[$i]->ReportItem as $issue) {
			$port =  $reports->Report->ReportHost[$i]->ReportItem[$count_issue]['port'] . "/" . $reports->Report->ReportHost[$i]->ReportItem[$count_issue]['protocol'];
			$name = $reports->Report->ReportHost[$i]->ReportItem[$count_issue]->plugin_name;
			$synopsis = cleanup_text($reports->Report->ReportHost[$i]->ReportItem[$count_issue]->synopsis);
			$risk_factor = $reports->Report->ReportHost[$i]->ReportItem[$count_issue]->risk_factor;
			$solution = cleanup_text($reports->Report->ReportHost[$i]->ReportItem[$count_issue]->solution);
			if ($risk_factor == "Critical") {
				$output_critical .= "<tr><td>$host</td><td>$name</td><td>$port</td><td class='critical'>$risk_factor</td><td>$synopsis</td><td>$solution</td><td> </td><td> </td></tr>";
				$count_critical++;
			}
			elseif ($risk_factor == "High") {
				$output_high .= "<tr><td>$host</td><td>$name</td><td>$port</td><td class='high'>$risk_factor</td><td>$synopsis</td><td>$solution</td><td> </td><td> </td></tr>";
				$count_high++;
			}
			elseif ($risk_factor == "Medium") {
				$output_medium .= "<tr><td>$host</td><td>$name</td><td>$port</td><td class='medium'>$risk_factor</td><td>$synopsis</td><td>$solution</td><td> </td><td> </td></tr>";
				$count_medium++;
			}
			elseif ($risk_factor == "Low") {
				$output_low .= "<tr><td>$host</td><td>$name</td><td>$port</td><td class='low'>$risk_factor</td><td>$synopsis</td><td>$solution</td><td> </td><td> </td></tr>";
				$count_low++;
			}

			if (strpos("$name","Compliance Check")) {
				$check_output_perline = "\"$host\",";
				$description = $reports->Report->ReportHost[$i]->ReportItem[$count_issue]->description;
				preg_match("/\[\w+\]/", $description, $output_array);
				$check_result = $output_array[0];
				if (strpos("$check_result","PASSED")) {
					$check_count_passed++;
				}
				elseif (strpos("$check_result","FAILED")) {
					$check_count_failed++;
				}
				if (strpos("$check_result","WARNING")) {
					$check_count_warning++;
				}
				$check_title = explode($check_result,$description);
				$check_title = str_replace("\"","",$check_title[0]);
				$check_title = str_replace(":","",$check_title);
				$check_output_perline .= "\"$check_title\",";
				$check_result = str_replace("[","",$check_result);
				$check_result = str_replace("]","",$check_result);
				$check_output_perline .= "\"$check_result\"";
				$check_main_output = $check_output_perline ."\n". $check_main_output;
			}

			$count_issue++;
		}
		$check_total_perhost .= "$host: $check_count_passed $check_count_failed $check_count_warning\n";
		$fileloop_output = "<h2 class='text-host'>$host</h2><h3 class='text-severity'>Critical Severity</h3>";
		if (substr_count($output_critical, 'tr>') > 2) {
			$fileloop_output .= "<table>$output_critical</table>";

		}
		else {
			$fileloop_output .= "n/a";

		}
		$fileloop_output .= "<h3 class='text-severity'>High Severity</h3>";
		if (substr_count($output_high, 'tr>') > 2) {
			$fileloop_output .= "<table>$output_high</table>";
		}
		else {
			$fileloop_output .= "n/a";
		}	

		$fileloop_output .= "<h3 class='text-severity'>Medium Severity</h3>";
		if (substr_count($output_medium, 'tr>') > 2) {
			$fileloop_output .= "<table>$output_medium</table>";
		}
		else {
			$fileloop_output .= "n/a";

		}

		$fileloop_output .= "<h3 class='text-severity'>Low Severity</h3>";
		if (substr_count($output_low, 'tr>') > 2) {
			$fileloop_output .= "<table>$output_low</table>";
		}
		else {
			$fileloop_output .= "n/a";

		}

		$output_critical = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
		$output_high = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
		$output_medium = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
		$output_low = "<tr><th>Host</th><th>Name</th><th>Port/Protocol</th><th>Risk</th><th>Synopsis</th><th>Solution</th><th>Action By</th><th>Review By</th></tr>";
		$count_row = $i + 1;
		$count_all = $count_critical + $count_high + $count_medium + $count_low;
		$issue_total = "<tr><td></td><td>$host</td><td>Vulnerability Assessment</td><td>$count_critical</td><td>$count_high</td><td>$count_medium</td><td>$count_low</td><td>$count_all</td></tr>";
		$all_issue_total .= $issue_total;
		$output .= $fileloop_output;
		$all_critical += $count_critical;
		$all_high += $count_high;
		$all_medium += $count_medium;
		$all_low += $count_low;
		$all_total += $count_all;
		//echo $i;
	}
}
$table_summary = "<br/><table><tr class='th_head'><th>No</th><th>IP Address</th><th>Type</th><th class='critical'>Critical</th><th class='high'>High</th><th class='medium'>Medium</th><th class='low'>Low</th><th class='total'>Total</th></tr>";
$table_summary .= $all_issue_total;
$table_summary .= "<tr class=''><td></td><td></td><td>Total</td><td>$all_critical</td><td>$all_high</td><td>$all_medium</td><td>$all_low</td><td>$all_total</td></tr></table><br/><br/>";
$output = $table_summary . $output;
$output_time = date("ymdHis");
$output_file = "output_$output_time.html";
file_put_contents($output_file, $output);

if (!empty($check_main_output)) {
	$check_output_file = "Compliance_Check.csv";
	$check_main_output = "\"Host\",\"CIS Checks\",\"Result\"\n" . $check_main_output;
	file_put_contents($check_output_file, $check_main_output);
	echo "$check_total_perhost\n";
}

?>
