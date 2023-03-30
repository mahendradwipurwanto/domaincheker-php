<?php

error_reporting(0);

function isPhishingWebsite($domain) {

  $score = 0;

  // Check number of dots in the domain
  if(isset($_POST['checks']['dots'])){
    // count how many dot on domain
    $dotCount = substr_count($domain, '.');
    // check if more than 3 dot it will decrase score
    if ($dotCount > 3) {
      $score--;
    } else {
      $score++;
    }
  }

  // Check for the presence of @ character
  if(isset($_POST['checks']['symbol'])){
    // check if there is @ in domain strin
    if (strpos($domain, '@') !== false) {
      $score--;
    } else {
      $score++;
    }
  }

  // Check if the domain is an IP address
  if(isset($_POST['checks']['ip'])){
    // check if domain is an IP address
    if (filter_var($domain, FILTER_VALIDATE_IP)) {
      $score--;
    } else {
      $score++;
    }
  }

  // Check how old the domain is
  if(isset($_POST['checks']['age'])){
    $whois = shell_exec("whois $domain");
    if (strpos($whois, 'Creation Date') === false) {
      $score--;
    } else {
      $score++;
    }
  }

  // Check the domain's certificate
  if(isset($_POST['checks']['ssl'])){

    // option config for stream
    $options = [
      'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false
      ]
    ];

    $port = 443;
    $scheme = 'ssl';
    $timeout = 30;

    // Access the socket
    $context = stream_context_create($options);
    $socket = stream_socket_client($scheme . '://' . $domain . ':' . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
    if ($socket === false) {
        $score--;
    } else {
        // Check the domain's certificate
        $context = stream_context_create(array("ssl" => array("capture_peer_cert" => true)));
        $stream = stream_socket_client($scheme . '://' . $domain . ':' . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $context);
        $params = stream_context_get_params($stream);
        // get certificate data
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        $validFrom = $cert['validFrom_time_t'];
        $validTo = $cert['validTo_time_t'];
        $currentTime = time();
        // check date of certificate is valid or not
        if ($currentTime < $validFrom || $currentTime > $validTo) {
            $score--;
        } else {
            $score++;
        }
    }
  }

  // Get the domain's metadata
  if(isset($_POST['checks']['meta'])){
    // Set the URL or domain name
    $url = $domain;
    if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
        $url = "http://" . $url;
    }
    $urlParts = parse_url($url);
    $url = preg_replace('/^www\./', '', $urlParts['host']);
    $metaTags = get_meta_tags("http://".$url);
    if ($metaTags === false) {
        $score--;
    }else{
      if(isset($metaTags['title'])){
        if (empty($metaTags['title'])) {
          $score--;
        } else {
          $score++;
        }
      }else{
        $score--;
      }

      if(isset($metaTags['description'])){
        if (empty($metaTags['description'])) {
          $score--;
        } else {
          $score++;
        }
      }else{
        $score--;
      }
    }
  }

  // Determine if the domain is a phishing website based on the score and threshold
  $threshold = 1;
  if ($score < $threshold) {
    $result = [
      'status' => true,
      'score' => $score
    ];
  } else {
    $result = [
      'status' => false,
      'score' => $score
    ];
  }

  return $result;
}

function checkDomains($filename, $type = 1) {
  $results = [];

  if($type == 1){
    // Read the list of domains from the file
    $domains = file($filename, FILE_IGNORE_NEW_LINES);
  
    // Check each domain for phishing
    foreach ($domains as $domain) {
      $isPhishing = isPhishingWebsite($domain);
      $result = [
        "domain" => $domain,
        "is_phishing" => $isPhishing['status'] ? "Website Phising" : "Bukan Phising",
        "score" => $isPhishing['score']
      ];
      $results[] = $result;
    }
  }else{
      $isPhishing = isPhishingWebsite($filename);
      $result = [
        "domain" => $filename,
        "is_phishing" => $isPhishing['status'] ? "Website Phising" : "Bukan Phising",
        "score" => $isPhishing['score']
      ];
      $results[] = $result;
  }

  // Create a new file with the results
  $outputFilename = "output.txt";
  $output = "";
  foreach ($results as $result) {
    $output .= "{$result['domain']} - {$result['is_phishing']}\n";
  }
  
  file_put_contents($outputFilename, $output);

  return [
    'data' => $results,
    'file' => $outputFilename
  ];
}

function ej($params){
  echo json_encode($params);

  exit;
}