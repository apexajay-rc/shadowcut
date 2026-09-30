# Tomorrow integration checklist

1. Copy the new files into the existing repository at the same paths.
2. Keep the existing controlled dashboard unchanged.
3. Run:
   `PYTHONPATH=./src pytest -q`
4. Run the existing console:
   `PYTHONPATH=./src streamlit run src/ui/dashboard.py`
5. For real LANL mode:
   `mkdir -p data/lanl`
6. Place official LANL files at:
   `data/lanl/auth.txt.gz`
   `data/lanl/redteam.txt.gz`
7. Run:
   `PYTHONPATH=./src python3 src/main_lanl.py --auth data/lanl/auth.txt.gz --redteam data/lanl/redteam.txt.gz`
8. Then:
   `PYTHONPATH=./src streamlit run src/ui/lanl_dashboard.py`

Important:
- Do not commit the LANL data files.
- Keep the controlled demo as the fallback.
- The LANL dashboard treats the red-team destination as the containment target for the selected scenario; it does not invent "critical asset" labels.
