# RiskNavigator HIPAA + SOC 2 Streamlit App

This package is GitHub and Streamlit Cloud ready.

## Files
- `app.py` - main Streamlit entrypoint
- `soc2_readiness.py` - scoring engine for SOC 2 and HIPAA
- `sample_data/hipaa_control_intake.csv` - sample HIPAA intake
- `hipaa_intake_workbook.xlsx` - client-facing HIPAA intake workbook

## Deploy to GitHub and Streamlit
1. Create a new GitHub repo.
2. Upload all files from this folder.
3. In Streamlit Cloud, create a new app and select `app.py`.
4. Add optional secrets using `.streamlit/secrets.toml.example`.

## Local run
```bash
pip install -r requirements.txt
streamlit run app.py
```

Demo fallback login: `admin / admin123`

## HIPAA intake format
Use the workbook tab named `Control Intake` or the sample CSV. Required columns:
- control_id
- control_area
- control_name
- in_scope
- status
- evidence_available
- owner_assigned
- policy_exists
- procedure_exists
- tested_recently

Optional columns can be added, such as `notes`.
