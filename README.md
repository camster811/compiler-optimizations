# compiler-optimizations
Research Project

The controlled pilot compares compiler optimization and symbol stripping effects on buffer-overflow analysis of Ghidra output. Build/oracle/extraction and static-baseline procedures are documented in [Current Findings and Reproduction Report.md](Current%20Findings%20and%20Reproduction%20Report.md).

The local DeepSeek/llama.cpp analyzer, blinded request contract, resumable pilot execution, private scoring, and method-freeze procedure are documented in [llm_analysis/README.md](llm_analysis/README.md).

The [frozen final-v1 corpus and inference handoff](datasets/final-v1/README.md) contains 20 new source pairs across O0/O1/O2/O3 and both symbol conditions: 320 planned observations, 216 eligible observations, and 176 distinct records. Compiler elimination and unavailable context are recorded separately; final LLM inference has not been run.
