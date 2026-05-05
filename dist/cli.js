#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var commander_1 = require("commander");
var program = new commander_1.Command();
var xmlbuilder2_1 = require("xmlbuilder2");
program
    .name("npm-audit-plus-plus")
    .description("A tool to capture the output of npm audit and convert it to xml")
    .version("1.1.1");
program
    .description("npm audit --json | npx npm-audit-plus-plus")
    .option("--debug", "display debug information")
    .option("-s, --severity [SEVERITY]", "Severity level to treat as error (low, mod, high), default: critical", "critical")
    .action(function () {
    // read the options
    var options = program.opts();
    // read the input
    process.stdin.resume();
    var rawInput = "";
    process.stdin.on("data", function (input) {
        rawInput += input;
    });
    // when input ends, parse the file
    process.stdin.on("end", function () {
        var input;
        try {
            input = JSON.parse(rawInput);
        }
        catch (e) {
            console.log("Error parsing JSON input");
            console.log(e);
            process.exit(1);
        }
        var critCount = input.metadata.vulnerabilities.critical;
        var highCount = input.metadata.vulnerabilities.high;
        var modCount = input.metadata.vulnerabilities.moderate;
        var lowCount = input.metadata.vulnerabilities.low;
        var infoCount = input.metadata.vulnerabilities.info;
        var depCount = input.metadata.dependencies;
        if (options.debug) {
            console.log(input);
            console.log({
                dependencies: depCount,
                critical: critCount,
                high: highCount,
                moderate: modCount,
                low: lowCount,
                info: infoCount,
            });
        }
        var xml;
        if (input.auditReportVersion == 2) {
            if (options.debug) {
                console.log("Using v2");
            }
            xml = v2(input, options.severity);
        }
        else {
            if (options.debug) {
                console.log("Using v1");
            }
            xml = v1(input, options.severity);
        }
        // when all ok, create success XML and short circuit
        console.log(xml);
        if (critCount > 0) {
            process.exit(1);
        }
        else {
            process.exit(0);
        }
    });
});
program.parse(process.argv);
var v1 = function (input, severity) {
    var critCount = input.metadata.vulnerabilities.critical;
    var highCount = input.metadata.vulnerabilities.high;
    var modCount = input.metadata.vulnerabilities.moderate;
    var lowCount = input.metadata.vulnerabilities.low;
    var infoCount = input.metadata.vulnerabilities.info;
    var depCount = input.metadata.dependencies;
    if (critCount === 0 &&
        highCount === 0 &&
        modCount === 0 &&
        lowCount === 0 &&
        infoCount === 0) {
        var empty = (0, xmlbuilder2_1.create)({ version: "1.0" })
            .ele("testsuites")
            .ele("testsuite", {
            name: "NPM Audit Summary v1",
            errors: 0,
            failures: 0,
            tests: 1,
        })
            .ele("testcase", {
            classname: "Summary",
            name: "Critical: 0, High: 0, Moderate: 0, Low: 0, Info: 0, Dependencies: ".concat(depCount),
        });
        return empty.end({ prettyPrint: true });
    }
    // else, some vulnerabilities were found, create failure XML
    var testcase = [
        {
            "@classname": "Summary",
            "@name": "Critical: ".concat(critCount, ", High: ").concat(highCount, ", Moderate: ").concat(modCount, ", Low: ").concat(lowCount, ", Info: ").concat(infoCount, ", Dependencies: ").concat(depCount),
            "@time": "0",
        },
    ];
    for (var advisory in input.advisories) {
        var failure = input.advisories[advisory].severity === "critical"
            ? {
                "@message": input.advisories[advisory].title +
                    " - " +
                    input.advisories[advisory].findings[0].version +
                    " - " +
                    input.advisories[advisory].findings[0].paths[0],
                "@type": "error",
                "#text": input.advisories[advisory].overview,
            }
            : null;
        testcase.push({
            "@name": input.advisories[advisory].title +
                "\n" +
                input.advisories[advisory].overview +
                "\n" +
                input.advisories[advisory].references,
            "@classname": input.advisories[advisory].module_name +
                "@" +
                input.advisories[advisory].vulnerable_versions +
                " (" +
                input.advisories[advisory].severity +
                ")",
            failure: failure,
        });
    }
    var errors = critCount;
    switch (severity) {
        case "low":
            errors = lowCount + modCount + highCount + critCount;
            break;
        case "mod":
            errors = modCount + highCount + critCount;
            break;
        case "high":
            errors = highCount + critCount;
            break;
    }
    var obj = {
        testsuites: {
            testsuite: {
                "@name": "NPM Audit Summary",
                "@errors": errors,
                "@failures": errors,
                "@tests": critCount + highCount + modCount + lowCount + infoCount,
                testcase: testcase,
            },
        },
    };
    var doc = (0, xmlbuilder2_1.create)(obj);
    return doc.end({ prettyPrint: true });
};
var v2 = function (input, severity) {
    var _a;
    var critCount = input.metadata.vulnerabilities.critical;
    var highCount = input.metadata.vulnerabilities.high;
    var modCount = input.metadata.vulnerabilities.moderate;
    var lowCount = input.metadata.vulnerabilities.low;
    var infoCount = input.metadata.vulnerabilities.info;
    var depCount = input.metadata.dependencies.total;
    if (critCount === 0 &&
        highCount === 0 &&
        modCount === 0 &&
        lowCount === 0 &&
        infoCount === 0) {
        var empty = {
            testsuites: {
                testsuite: {
                    "@name": "NPM Audit Summary v2",
                    "@errors": critCount,
                    "@failures": 0,
                    "@tests": depCount,
                    testcase: {
                        "@classname": "Summary",
                        "@name": "Critical: ".concat(critCount, ", High: ").concat(highCount, ", Moderate: ").concat(modCount, ", Low: ").concat(lowCount, ", Info: ").concat(infoCount, ", Dependencies: ").concat(depCount),
                        "@time": "0",
                    },
                },
            },
        };
        var doc_1 = (0, xmlbuilder2_1.create)(empty);
        return doc_1.end({ prettyPrint: true });
    }
    // when critical vulnerabilities are found, create failure XML
    var vulnerabilities = ((_a = input.vulnerabilities) !== null && _a !== void 0 ? _a : {});
    var testcase = Object.values(vulnerabilities).map(function (vulnerability) { return ({
        "@package": vulnerability.name,
        "@name": vulnerability.name,
        "@severity": vulnerability.severity,
        "@time": "0",
        "failure": vulnerability.via.map(function (v) { return ViaProcessor(vulnerability, v); }),
    }); });
    var errors = critCount;
    switch (severity) {
        case "low":
            errors = lowCount + modCount + highCount + critCount;
            break;
        case "mod":
            errors = modCount + highCount + critCount;
            break;
        case "high":
            errors = highCount + critCount;
            break;
    }
    var root = {
        testsuite: {
            "@name": "NPM Audit Summary v2",
            "@errors": errors,
            "@failures": 0,
            "@tests": depCount,
            testcase: testcase,
        },
    };
    var doc = (0, xmlbuilder2_1.create)(root);
    return doc.end({ prettyPrint: true });
};
function ViaProcessor(vulnerability, via) {
    var result = ViaObjectProcessor(vulnerability, via);
    if (result) {
        return result;
    }
    return ViaStringProcessor(vulnerability, via);
}
function ViaObjectProcessor(vulnerability, via) {
    if (typeof via === "string") {
        return undefined;
    }
    var messages = "".concat(via.title, "\n\nSeverity: ").concat(via.severity, "\nDirect dependency: ").concat(vulnerability.isDirect, "\nVersion: ").concat(via.range, "\nUrl: ").concat(via.url, "\n\nCWE: \n").concat(via.cwe.join("\n"), "\n\nResolution: ").concat(ParseResolution(vulnerability.fixAvailable), "\n");
    return {
        "@type": "error",
        "#text": messages,
    };
}
function ViaStringProcessor(vulnerability, via) {
    if (typeof via !== "string") {
        return undefined;
    }
    var messages = "".concat(via, "\n\nSeverity: ").concat(vulnerability.severity, "\nDirect dependency: ").concat(vulnerability.isDirect, "\nVersion: ").concat(vulnerability.range, "\n");
    return {
        "@type": "error",
        "#text": messages,
    };
}
function ParseResolution(resolution) {
    if (typeof resolution === "boolean") {
        return "true";
    }
    return "".concat(resolution.name, " (").concat(resolution.version, ")");
}
