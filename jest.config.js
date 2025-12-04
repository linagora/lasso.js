/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  transform: {
    "^.+\\.tsx?$": "ts-jest",
  },
  testMatch: ["**/test/**/*.test.ts"],
  collectCoverageFrom: ["lib/**/*.ts"],
  coverageDirectory: "coverage",
  coverageReporters: ["text", "lcov"],
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
};
