# PyCript - Burp Suite Extension

## Overview
PyCript is a Burp Suite extension designed to enhance your web application security testing capabilities. This project is built using Java and integrates seamlessly with Burp Suite.

## Project Structure
```
PyCript
├── src
│   ├── main
│   │   ├── java
│   │   │   └── com
│   │   │       └── pycript
│   │   │           └── Main.java
│   │   └── resources
│   └── test
│       ├── java
│       └── resources
├── build.gradle
├── settings.gradle
└── README.md
```

## Getting Started

### Prerequisites
- Java Development Kit (JDK) 8 or higher
- Gradle 6.0 or higher
- Burp Suite (Community or Professional)

### Building the Project
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/PyCript.git
   ```
2. Navigate to the project directory:
   ```
   cd PyCript
   ```
3. Build the project using Gradle:
   ```
   ./gradlew build
   ```

### Running the Extension
1. Open Burp Suite.
2. Go to the "Extensions" tab.
3. Click on "Add" and select "Java" as the extension type.
4. Choose the compiled JAR file from the `build/libs` directory.

## Testing
Unit tests are located in the `src/test/java` directory. You can run the tests using Gradle:
```
./gradlew test
```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bugs.

## License
This project is licensed under the MIT License. See the LICENSE file for details.