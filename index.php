<?php

require_once('functions.php');

if($_SERVER['REQUEST_METHOD'] == 'POST') {

    // check if submit url domain
    if (isset($_POST['submit_url'])) {
        $results = checkDomains($_POST['domains_url'], 0);
    }

    // check if submit file
    if (isset($_POST['submit_file'])){
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
                $results = checkDomains($tempFilepath, 1);
            }
        } else {
            echo "<script>alert('Failed upload file.');</script>";
        }
    }
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>Cek Domain Phishing</title>
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
        <h1 class="my-4">Cek URL Phising</h1>
        <form method="post" enctype="multipart/form-data" onsubmit="showLoader()" id="domains_form">
            <div class="mb-3">
                <div class="row">
                    <div class="col-6">
                        <label for="domains_url" class="form-label">Input URL:</label>
                        <div class="mb-3 text-center">
                            <input type="text" class="form-control mb-3" name="domains_url" id="domains_url"
                                accept=".txt">
                            <button type="submit" class="btn btn-primary btn-sm" name="submit_url">Proses</button>
                        </div>
                    </div>
                    <div class="col-6">
                        <label for="domains_file" class="form-label">Input file berupa text:</label>
                        <div class="mb-3 text-center">
                            <input type="file" class="form-control mb-3" name="domains_file" id="domains_file"
                                accept=".txt">
                            <button type="submit" class="btn btn-primary btn-sm" name="submit_file">Proses</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row mb-3">
                <label class="form-label">Pilih kategori/kriteria dari phising:</label>
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[dots]" value="dots" id="check-dots"
                            <?php if(isset($_POST['checks']) && in_array('dots', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-dots">
                            Jumlah Dot
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[symbol]" value="symbol"
                            id="check-at-symbol"
                            <?php if(isset($_POST['checks']) && in_array('symbol', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-at-symbol">
                            Penggunaan @
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[ip]" value="ip"
                            id="check-ip-address"
                            <?php if(isset($_POST['checks']) && in_array('ip', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-ip-address">
                            IP address
                        </label>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[age]" value="age" id="check-age"
                            <?php if(isset($_POST['checks']) && in_array('age', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-age">
                            Usia domain
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[ssl]" value="ssl" id="check-ssl"
                            <?php if(isset($_POST['checks']) && in_array('ssl', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-ssl">
                            Sertifikat SSL
                        </label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="checks[meta]" value="meta"
                            id="check-meta-tags"
                            <?php if(isset($_POST['checks']) && in_array('meta', $_POST['checks'])) echo 'checked'; ?>>
                        <label class="form-check-label checkbox-label" for="check-meta-tags">
                            Meta tags dari domain
                        </label>
                    </div>
                </div>
            </div>
        </form>
        <?php if (isset($results['data'])): ?>
        <h2 class="my-4">Results</h2>
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th scope="col">Url</th>
                        <th scope="col">Hasil/Output</th>
                        <!-- <th scope="col">Score</th> -->
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results['data'] as $result): ?>
                    <tr>
                        <td><?= $result['domain'] ?></td>
                        <td><?= $result['is_phishing'] ?></td>
                        <!-- <td><?= $result['score'] ?></td> -->
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
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