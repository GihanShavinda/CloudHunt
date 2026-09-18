import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Subscription } from 'rxjs';
import { ApiService } from '../api.service';
import { FeedService } from '../feed.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page-heading">
      <div>
        <div class="eyebrow">OVERVIEW</div>
        <h1>Security Dashboard</h1>
        <p>Cloud identity risk, active detections, blast radius and response readiness.</p>
      </div>
      <div class="heading-actions">
        <a routerLink="/detections" class="button-link secondary">View detections</a>
        <a routerLink="/iam-graph" class="button-link">Explore IAM graph</a>
      </div>
    </div>

    <div class="kpi-grid">
      <a routerLink="/cases" class="panel kpi-card panel-accent clickable-card">
        <div class="kpi-top"><span class="kpi-icon">◇</span><span class="badge badge-info">CASES</span></div>
        <div class="metric">{{ summary?.open_cases ?? summary?.cases_by_blast?.length ?? 0 }}</div>
        <strong>Active security cases</strong>
        <p>Ranked by blast radius × confidence.</p>
      </a>

      <a routerLink="/detections" class="panel kpi-card clickable-card">
        <div class="kpi-top"><span class="kpi-icon purple">⌁</span><span class="badge badge-purple">M8+</span></div>
        <div class="metric metric-cyan">{{ advanced.length }}</div>
        <strong>Advanced findings</strong>
        <p>Drift, trust-policy and S3 exfil analytics.</p>
      </a>

      <a routerLink="/iam-graph" class="panel kpi-card clickable-card">
        <div class="kpi-top"><span class="kpi-icon cyan">◎</span><span class="badge badge-info">IAM</span></div>
        <div class="metric">{{ sensitiveCount() }}</div>
        <strong>Sensitive exposures</strong>
        <p>Graph-reachable high-sensitivity resources.</p>
      </a>

      <div class="panel kpi-card">
        <div class="kpi-top"><span class="kpi-icon" [class.red]="!summary?.logging_health?.healthy">◉</span><span class="badge" [class.badge-success]="summary?.logging_health?.healthy" [class.badge-danger]="!summary?.logging_health?.healthy">LOGGING</span></div>
        <div class="metric" [class.metric-danger]="!summary?.logging_health?.healthy">{{ summary?.logging_health?.healthy ? 'HEALTHY' : 'DEGRADED' }}</div>
        <strong>Audit telemetry</strong>
        <p>{{ summary?.logging_health?.healthy ? 'All known trails are reporting.' : 'Cloud logging requires investigation.' }}</p>
      </div>
    </div>

    <div class="dashboard-layout">
      <section class="panel span-8">
        <div class="section-title-row">
          <div><div class="eyebrow">TRIAGE QUEUE</div><h2>Cases by Blast Radius</h2></div>
          <a routerLink="/cases">Open case queue →</a>
        </div>
        <div class="table-wrap" *ngIf="summary?.cases_by_blast?.length; else noCases">
          <table>
            <thead><tr><th>Case</th><th>Confidence</th><th>Blast radius</th><th>Rank</th><th></th></tr></thead>
            <tbody>
              <tr *ngFor="let c of summary.cases_by_blast">
                <td><a class="table-primary" [routerLink]="['/case', c.case_id]">{{ c.title || c.case_id }}</a><div class="muted small mono">{{ c.case_id }}</div></td>
                <td><span class="badge badge-info">{{ (c.confidence * 100) | number:'1.0-0' }}%</span></td>
                <td style="min-width:170px"><div class="score-row"><div class="bar"><i [style.width.%]="c.blast"></i></div><strong>{{ c.blast | number:'1.0-0' }}</strong></div></td>
                <td>{{ c.rank | number:'1.2-2' }}</td>
                <td><a class="row-action" [routerLink]="['/case', c.case_id]">Investigate →</a></td>
              </tr>
            </tbody>
          </table>
        </div>
        <ng-template #noCases><div class="empty-state"><span>◇</span><strong>No active cases</strong><p>Replay a scenario or ingest telemetry to populate the queue.</p></div></ng-template>
      </section>

      <section class="panel span-4">
        <div class="section-title-row"><div><div class="eyebrow">TELEMETRY</div><h2>Logging Health</h2></div><span class="status-dot" [class.danger-dot]="!summary?.logging_health?.healthy"></span></div>
        <div *ngFor="let t of summary?.logging_health?.trails" class="health-row">
          <div><strong>{{ t.trail }}</strong><small>CloudTrail</small></div>
          <span class="badge" [class.badge-success]="t.logging" [class.badge-danger]="!t.logging">{{ t.logging ? '● LOGGING' : '● STOPPED' }}</span>
        </div>
        <div class="empty-inline" *ngIf="!summary?.logging_health?.trails?.length">No trail details available.</div>
      </section>

      <section class="panel span-6">
        <div class="section-title-row"><div><div class="eyebrow">EXPOSURE</div><h2>Sensitive Resources</h2></div><a routerLink="/iam-graph">Graph view →</a></div>
        <div *ngFor="let e of summary?.sensitive_resource_exposure" class="finding-row">
          <span class="severity-icon critical">!</span>
          <div class="finding-content"><strong>{{ short(e.resource) }}</strong><div class="muted small mono">{{ e.resource }}</div><div class="tag-line"><span class="badge badge-danger">{{ e.sensitivity }}</span><span class="badge">reachable by {{ e.reachable_by?.length || 0 }} principal(s)</span></div></div>
        </div>
        <div class="empty-state compact-empty" *ngIf="!summary?.sensitive_resource_exposure?.length"><span>✓</span><strong>No current sensitive exposure</strong></div>
      </section>

      <section class="panel span-6">
        <div class="section-title-row"><div><div class="eyebrow">ADVANCED ANALYTICS</div><h2>Latest Findings</h2></div><a routerLink="/detections">All detections →</a></div>
        <div *ngFor="let d of advanced.slice(0,4)" class="finding-row">
          <span class="severity-icon high">⌁</span>
          <div class="finding-content"><a [routerLink]="['/case', d.case_id]"><strong>{{ d.title }}</strong></a><div class="muted small">{{ short(d.principal) }}{{ d.resource ? ' → ' + short(d.resource) : '' }}</div><div class="tag-line"><span class="badge badge-info" *ngFor="let t of d.attack_ids">{{ t }}</span></div></div>
        </div>
        <div class="empty-state compact-empty" *ngIf="!advanced.length"><span>✓</span><strong>No advanced findings</strong></div>
      </section>

      <section class="panel span-12">
        <div class="section-title-row"><div><div class="eyebrow">REAL TIME</div><h2>Live Case Feed</h2></div><span class="badge badge-info">WEBSOCKET</span></div>
        <div class="live-feed">
          <div *ngFor="let m of feedLog.slice(0,8)" class="feed-item"><span class="feed-pulse"></span><span class="mono">{{ m }}</span></div>
          <div class="muted" *ngIf="!feedLog.length">Waiting for live case events…</div>
        </div>
      </section>
    </div>
  `,
})
export class DashboardComponent implements OnInit, OnDestroy {
  summary: any;
  feedLog: string[] = [];
  advanced: any[] = [];
  private sub?: Subscription;

  constructor(private api: ApiService, private feed: FeedService) {}

  ngOnInit(): void {
    this.refresh();
    this.sub = this.feed.connect().subscribe({
      next: (m) => {
        this.feedLog.unshift(m.type === 'snapshot' ? `snapshot · ${m.cases.length} case(s)` : `${m.type} · ${m.case_id}`);
        this.feedLog = this.feedLog.slice(0, 20);
        if (m.type === 'case_updated') this.refresh();
      },
      error: () => this.feedLog.unshift('feed disconnected'),
    });
  }

  private refresh(): void {
    this.api.dashboard().subscribe((s) => {
      this.summary = s;
      this.advanced = [];
      for (const c of s.cases_by_blast || []) {
        this.api.caseDetail(c.case_id).subscribe((d) => {
          for (const finding of d.advanced_detections || []) {
            this.advanced.push({ ...finding, case_id: c.case_id });
          }
        });
      }
    });
  }

  sensitiveCount(): number {
    return this.summary?.sensitive_resource_exposure?.length || 0;
  }

  short(value: string | null | undefined): string {
    if (!value) return '';
    return value.split('/').pop() || value;
  }

  ngOnDestroy(): void {
    this.sub?.unsubscribe();
  }
}
