const { exec } = require('child_process');

// Function to run the C++ executable
function runSha256(baseString, k) {
    // Run the C++ executable with the base string and number of leading zeros
    exec(`./mul "${baseString}" ${k}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`stderr: ${stderr}`);
            return;
        }
        // Log the output from the C++ program
        console.log(`Output: ${stdout.trim()}`);
    });
}

// Example usage
runSha256("test", 5);
