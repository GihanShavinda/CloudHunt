import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { forkJoin, of } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { ApiService } from '../api.service';

@Component({
  selector: 'app-detections',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="page-heading">
      <div><div class="eyebrow">DETECTION ENGINE</div><h1>Detections</h1><p>Signature, behavioural, correlation and advanced cloud-security findings.</p></div>
      <div class="summary-pills"><span class="badge badge-danger">{{ criticalCount() }} critical/high</span><span class="badge badge-purple">{{ advancedCount() }} advanced</span><span class="badge badge-info">{{ filtered().length }} shown</span></div>
    </div>

    <div class="detection-stats">
      <div class="panel mini-stat"><small>Total detections</small><strong>{{ detections.length }}</strong></div>
      <div class="panel mini-stat"><small>Signature</small><strong>{{ countLayer('signature') }}</strong></div>
      <div class="panel mini-stat"><small>Behavioural</small><strong>{{ countLayer('behavioural') }}</strong></div>
      <div class="panel mini-stat"><small>Correlation</small><strong>{{ countLayer('correlation') }}</strong></div>
      <div class="panel mini-stat"><small>ATT&CK techniques</small><strong>{{ attackIds().length }}</strong></div>
    </div>

    <div class="filter-bar panel">
      <div class="search-field"><span>⌕</span><input [(ngModel)]="query" placeholder="Search title, principal, resource, ATT&CK ID…" /></div>
      <select [(ngModel)]="layer"><option value="all">All layers</option><option value="signature">Signature</option><option value="behavioural">Behavioural</option><option value="correlation">Correlation</option></select>
      <select [(ngModel)]="kind"><option value="all">All detections</option><option value="advanced">Advanced M8 only</option><option value="standard">Core detections</option></select>
    </div>

    <section class="panel">
      <div class="table-wrap detection-table">
        <table>
          <thead><tr><th>Severity</th><th>Detection</th><th>Layer</th><th>Principal / Resource</th><th>ATT&CK</th><th>Confidence</th><th>Case</th></tr></thead>
          <tbody>
            <tr *ngFor="let d of filtered()">
              <td><span class="badge" [class.badge-danger]="d.confidence >= .85" [class.badge-warning]="d.confidence >= .65 && d.confidence < .85" [class.badge-info]="d.confidence < .65">{{ severity(d.confidence) }}</span></td>
              <td><strong>{{ d.title }}</strong><div class="muted small">{{ d.message }}</div><span class="badge badge-purple" *ngIf="d.key?.startsWith('m8-')">ADVANCED</span></td>
              <td><span class="badge">{{ d.layer }}</span></td>
              <td><div>{{ short(d.principal) || '—' }}</div><div class="muted small mono">{{ short(d.resource) }}</div></td>
              <td><span class="badge badge-info" *ngFor="let t of d.attack_ids">{{ t }}</span></td>
              <td><div class="confidence-cell"><div class="bar"><i [style.width.%]="d.confidence * 100"></i></div><strong>{{ d.confidence * 100 | number:'1.0-0' }}%</strong></div></td>
              <td><a [routerLink]="['/case', d.case_id]">{{ d.case_id }} →</a></td>
            </tr>
            <tr *ngIf="!filtered().length"><td colspan="7"><div class="empty-state compact-empty"><span>⌁</span><strong>No matching detections</strong></div></td></tr>
          </tbody>
        </table>
      </div>
    </section>
  `,
})
export class DetectionsComponent implements OnInit {
  detections: any[] = [];
  query = '';
  layer = 'all';
  kind = 'all';

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.cases().pipe(
      switchMap((r) => {
        const cases = r.cases || [];
        if (!cases.length) return of([]);
        return forkJoin<any[]>(cases.map((c: any) => this.api.caseDetail(c.case_id)));
      }),
    ).subscribe((details) => {
      this.detections = details.flatMap((d) => (d.detections || []).map((x: any) => ({ ...x, case_id: d.case_id, case_title: d.title })));
    });
  }

  filtered(): any[] {
    const q = this.query.trim().toLowerCase();
    return this.detections.filter((d) => {
      const hay = `${d.title} ${d.key} ${d.principal || ''} ${d.resource || ''} ${(d.attack_ids || []).join(' ')} ${d.message || ''}`.toLowerCase();
      const qOk = !q || hay.includes(q);
      const layerOk = this.layer === 'all' || d.layer === this.layer;
      const advanced = d.key?.startsWith('m8-');
      const kindOk = this.kind === 'all' || (this.kind === 'advanced' ? advanced : !advanced);
      return qOk && layerOk && kindOk;
    }).sort((a, b) => b.confidence - a.confidence);
  }

  countLayer(layer: string): number {
    return this.detections.filter((d) => d.layer === layer).length;
  }

  advancedCount(): number {
    return this.detections.filter((d) => d.key?.startsWith('m8-')).length;
  }

  criticalCount(): number {
    return this.detections.filter((d) => d.confidence >= .85).length;
  }

  attackIds(): string[] {
    return [...new Set(this.detections.flatMap((d) => d.attack_ids || []))];
  }

  severity(confidence: number): string {
    if (confidence >= .90) return 'Critical';
    if (confidence >= .85) return 'High';
    if (confidence >= .65) return 'Medium';
    return 'Low';
  }

  short(value: string | null | undefined): string {
    if (!value) return '';
    return value.split('/').pop() || value;
  }
}
