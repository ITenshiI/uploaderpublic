<?php
// test_upload.php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['file'])) {
        echo "No file uploaded";
        exit;
    }

    $uploadDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadDir)) mkdir($uploadDir, 0775, true);

    $fileName = basename($_FILES['file']['name']);
    $target = $uploadDir . $fileName;

    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "OK — saved as {$target}";
    } else {
        echo "FAIL — check folder permissions and PHP settings";
        var_dump($_FILES);
    }
} else {
    ?>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    <?php
}