#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <vector>
#include <string>

using namespace std;
namespace fs = std::filesystem;

struct MalwareRule {
    string name;
    string description;
    vector<string> stringRules;
    vector<regex> regexRules;
};

string readFile(const string &path) {
    ifstream file(path, ios::binary);

    if (!file) {
        return "";
    }

    return string((istreambuf_iterator<char>(file)),
                  istreambuf_iterator<char>());
}

MalwareRule loadRule(const string &path) {
    MalwareRule rule;

    ifstream file(path);

    string line;

    while (getline(file, line)) {

        if (line.rfind("Name=", 0) == 0)
            rule.name = line.substr(5);

        else if (line.rfind("Description=", 0) == 0)
            rule.description = line.substr(12);

        else if (line.rfind("STRING:", 0) == 0)
            rule.stringRules.push_back(line.substr(7));

        else if (line.rfind("REGEX:", 0) == 0)
            rule.regexRules.push_back(regex(line.substr(6)));
    }

    return rule;
}

bool detectMalware(const string &content, MalwareRule &rule) {

    for (auto &s : rule.stringRules) {
        if (content.find(s) == string::npos)
            return false;
    }

    for (auto &r : rule.regexRules) {
        if (!regex_search(content, r))
            return false;
    }

    return true;
}

int main(int argc, char *argv[]) {

    if (argc != 3) {
        cout << "Usage: scanner <sourcefile> <rulesfolder>\n";
        return 0;
    }

    string sourceFile = argv[1];
    string rulesFolder = argv[2];

    string content = readFile(sourceFile);

    bool found = false;

    for (auto &entry : fs::recursive_directory_iterator(rulesFolder)) {

        if (entry.path().extension() == ".rule") {

            MalwareRule rule = loadRule(entry.path().string());

            if (detectMalware(content, rule)) {

                found = true;

                cout << "========================\n";
                cout << "Malware Detected\n";
                cout << "Name : " << rule.name << endl;
                cout << "Description : " << rule.description << endl;
            }
        }
    }

    if (!found) {
        cout << "No malware detected.\n";
    }

    return 0;
}