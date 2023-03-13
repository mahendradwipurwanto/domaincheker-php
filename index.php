<?php

require_once('functions.php');

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['domains_file'])) {
  // Check if file was uploaded successfully
  if($_FILES['domains_file']['error'] == 0) {
    $file = $_FILES['domains_file']['tmp_name'];
    $domains = array_map('trim', file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));

    // Check if there are more than 10 domains
    if(count($domains) > 10) {
      echo "<script>alert('Maximum 10 domains are allowed in one upload.');</script>";
    } else {
      // Process the domains
      // Get the uploaded file and move it to the server's temp directory
      $file = $_FILES['domains_file'];
      $tempFilename = $file['tmp_name'];
      $tempFilepath = tempnam(sys_get_temp_dir(), 'domains_');
      move_uploaded_file($tempFilename, $tempFilepath);

      // Call the checkDomains function with the temp file path
      $results = checkDomains($tempFilepath);
    }
  } else {
      echo "<script>alert('Failed upload file.');</script>";
  }
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>Phishing Checker</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <!-- Loader -->
    <div id="loader-wrapper">
        <div id="loader"></div>
        <div class="loader-section section-left"></div>
        <div class="loader-section section-right"></div>
    </div>
    <div class="container">
        <h1 class="my-4">Phishing Checker</h1>
        <form method="post" enctype="multipart/form-data" onsubmit="showLoader()" id="domains_form">
            <div class="row mb-3">
                <label class="form-label">Select the checks to perform:</label>
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[dots]" value="dots" id="check-dots"
                            <?php if(isset($_POST['checks']) && in_array('dots', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-dots">
                            Number of dots
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[symbol]" value="symbol"
                            id="check-at-symbol"
                            <?php if(isset($_POST['checks']) && in_array('symbol', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-at-symbol">
                            Presence of symbol @
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[ip]" value="ip"
                            id="check-ip-address"
                            <?php if(isset($_POST['checks']) && in_array('ip', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-ip-address">
                            If IP address
                        </label>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[age]" value="age" id="check-age"
                            <?php if(isset($_POST['checks']) && in_array('age', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-age">
                            How old is the domain
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[ssl]" value="ssl" id="check-ssl"
                            <?php if(isset($_POST['checks']) && in_array('ssl', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-ssl">
                            SSL certificate
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[meta]" value="meta"
                            id="check-meta-tags"
                            <?php if(isset($_POST['checks']) && in_array('meta', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-meta-tags">
                            Meta tags of domain
                        </label>
                    </div>
                </div>
            </div>
            <div class="mb-3">
                <label for="domains_file" class="form-label">Upload a text file containing a list of domains:</label>
                <input type="file" class="form-control" name="domains_file" id="domains_file" accept=".txt" required>
            </div>
            <button type="submit" class="btn btn-primary" name="submit">Check Domains</button>
            <a href="example.txt" download class="btn btn-info text-white my-4">Download Example file</a>
        </form>
        <?php if (isset($results['data'])): ?>
        <h2 class="my-4">Results</h2>
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th scope="col">Domain</th>
                        <th scope="col">Is Phishing?</th>
                        <th scope="col">Score</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results['data'] as $result): ?>
                    <tr>
                        <td><?= $result['domain'] ?></td>
                        <td><?= $result['is_phishing'] ?></td>
                        <td><?= $result['score'] ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <a href="<?= $results['file'] ?>" download class="btn btn-primary my-4">Download Results</a>
        <?php endif; ?>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.0/js/bootstrap.bundle.min.js"></script>
    <script>
        function showLoader() {
            document.getElementById("domains_form").style.display = "none";
            document.getElementById("loader-wrapper").style.display = "block";
        }
    </script>
</body>

</html>