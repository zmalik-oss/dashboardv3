# Cloud component (AWS plan)

AIT 670 is a cloud security course and the project must show technical work in the cloud. The pipeline
itself is plain Python and runs anywhere; this plan puts the data, the compute and the dashboard in AWS so
the cloud part is unambiguous. **This plan has not been tested.** Treat the steps as a starting outline
and adjust to the accounts and credits your group has.

## Minimal architecture

```
BETH CSVs -> S3 (raw) -> EC2 or SageMaker notebook runs `python -m triage benchmark`
                              |-> S3 (artifacts: report.md, metrics.json, review_queue.csv)
                              |-> S3 static site (dashboard/index.html + results.js)
S3 raw -> Athena table (optional) for SQL exploration of the same events
```

## Steps

1. **Account and budget.** Use a throwaway or class account. Set an AWS Budgets alert before anything else. Check whether the course provides credits.
2. **S3 buckets.** One private bucket for data and artifacts, with Block Public Access on and default encryption (SSE-S3). Upload the three CSVs.
3. **Compute.** A small EC2 instance (or a SageMaker notebook) with an IAM role that can read and write only that bucket. No access keys on the machine; use the role. Clone the repo, `pip install -e .`, run the benchmark, copy results back to S3. The full BETH train split is large, so use enough memory (several GB) or test with `--nrows` first.
4. **Athena (optional).** Create a table over the CSVs and run a few queries (events per process, failed `setuid` calls) to show SQL-based exploration.
5. **Dashboard hosting.** Simplest safe option: keep the bucket private and show the dashboard locally from the downloaded `dashboard/` folder during the demo. If you want a public URL, use a *separate* bucket or CloudFront with only `index.html` and `results.js`, and confirm `results.js` holds no data you are not allowed to share.

## Security hygiene worth showing in the report

- Least-privilege IAM role scoped to one bucket
- Block Public Access and encryption on the data bucket
- CloudTrail enabled on the account, so the project's own cloud activity is auditable
- No credentials in the repo (`.gitignore` covers `kaggle.json`, `.env`, keys)

## Demo idea

Run the scoring on the test split in the cloud, then open the dashboard and walk through one High group,
one Medium group, and one entry from the label-disagreements tab. Keep a recorded demo as a backup.
