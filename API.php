<?php

// Database connection setup
$con = mysqli_connect("localhost","root","","APICRUD");
$response = array();

if($con) {
    $sql = 'select * from user';
    $result = mysqli_query($con, $sql);

    if($result) {
        // Build JSON response from database results
        $x = 0;
        while($row = mysqli_fetch_assoc($result)) {
            $response[$x]['id']= $row['id'];
            $response[$x]['name']= $row['name'];
            $response[$x]['age']= $row['age'];
            $response[$x]['email']= $row['email'];
            $x++;
        }
        
        echo json_encode($response, JSON_PRETTY_PRINT);
    } 
}
else {
    echo 'Database connection failed';
}

?>