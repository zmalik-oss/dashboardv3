# AIT 670 deliverables checklist

Source: the AIT 670 group project instructions. Re-read them for anything not captured here.

## Graded stages

| Stage | Due | Weight | Requirement |
|---|---|---|---|
| Topic selection | Week 2 | 20% | Rep emails the instructor up to three topics in preference order; instructor approves one |
| Proposal | Week 4 | 20% | Max 1 page, professionally formatted: introduction, body, conclusion |
| Final report and presentation | Week 14 | 60% | Report max 10 pages; presentation 20 min plus 5 min questions; overtime is penalized |

Grades are adjusted up or down by peer review.

## Proposal (1 page)

- **Introduction:** security teams drown in host events; goal is to rank them by risk so analysts see what matters.
- **Body:** four-factor weighted rubric, action grouping, learned baseline, BETH benchmark, dashboard, AWS deployment.
- **Conclusion:** measurable outcomes: detection vs. labels, false-alarm rate, analyst workload reduction.

## Final report (max 10 pages), suggested outline

1. Goal and problem (half page)
2. Background and rubric theory: risk scoring methods, the four factors and point scales (this is where theory belongs, not the talk)
3. Dataset: BETH, splits, columns, the `sus`/`evil` labels
4. Implementation: grouping, baseline, rules, dashboard, cloud deployment
5. Benchmark protocol and results (real BETH numbers only)
6. Label-disagreement case studies, including the sshd example
7. Limitations and future work (lineage, process-name spoofing, one test host)
8. Contributions and references

## Presentation (20 + 5 minutes)

- Short background, then straight to the implementation. Theory stays in the report.
- **A demo is required** (live, or recorded with narration). Suggested flow: raw events -> one High group expanded in the dashboard (four factor bars and reasons) -> label-disagreements tab -> results slide.
- **No reading from a script.** Notes are allowed.
- **Online sections:** record together as a group; every member must speak; no separate recordings, merging or editing; introduce yourselves; put your name on every slide you present; include a recorded demo; submit the video with the report and slides.
- **In-class sections:** presented in class in week 14.

Confirm which section the group is in, and the exact due dates, with the instructor.

## Group process requirements

- Meet at least once every two weeks from week 2; at least 6 meetings plus the final presentation.
- Attendance is mandatory and recorded; it feeds the peer review.
- After **every** meeting the group representative emails the instructor the attendance record and a summary of deliberations.
- Each student submits a peer review form.

### Meeting record template

```
Meeting #:        Date:        Platform:
Attendees:        Absent:
Decisions:
Action items (owner, due):
Next meeting:
```
