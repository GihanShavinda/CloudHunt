import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../api.service';

@Component({
  selector: 'app-cases',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="page-heading">
      <div><div class="eyebrow">INCIDENT TRIAGE</div><h1>Security Cases</h1><p>Correlated attack stories ranked by potential cloud impact.</p></div>
      <span class="badge badge-info">{{ filteredCases().length }} visible</span>
    </div>

    <div class="filter-bar panel">
      <div class="search-field"><span>⌕</span><input [(ngModel)]="query" placeholder="Search case, technique or ID…" /></div>
      <select [(ngModel)]="riskFilter"><option value="all">All blast levels</option><option value="critical">Critical ≥ 70</option><option value="high">High 50–69</option><option value="medium">Medium 30–49</option><option value="low">Low &lt; 30</option></select>
      <select [(ngModel)]="actionFilter"><option value="all">All approval states</option><option value="pending">Pending human action</option><option value="clear">No pending action</option></select>
    </div>

    <div class="case-card-grid">
      <a class="panel case-card clickable-card" *ngFor="let c of filteredCases()" [routerLink]="['/case', c.case_id]">
        <div class="case-card-top">
          <span class="badge" [class.badge-danger]="c.blast >= 70" [class.badge-warning]="c.blast >= 40 && c.blast < 70" [class.badge-success]="c.blast < 40">{{ severity(c.blast) }}</span>
          <span class="muted small mono">{{ c.case_id }}</span>
        </div>
        <h3>{{ c.title || c.case_id }}</h3>
        <div class="case-metrics">
          <div><small>Blast radius</small><strong>{{ c.blast | number:'1.0-0' }}</strong></div>
          <div><small>Confidence</small><strong>{{ (c.confidence * 100) | number:'1.0-0' }}%</strong></div>
          <div><small>Pending</small><strong>{{ c.pending_actions || 0 }}</strong></div>
        </div>
        <div class="bar"><i [style.width.%]="c.blast"></i></div>
        <div class="tag-line"><span class="badge badge-info" *ngFor="let t of c.techniques">{{ t }}</span><span class="badge badge-danger" *ngIf="c.sensitive_exposed">Sensitive exposure</span></div>
        <div class="case-open">Open investigation →</div>
      </a>
    </div>

    <div class="empty-state panel" *ngIf="!filteredCases().length"><span>◇</span><strong>No matching cases</strong><p>Change the filters or replay a scenario to generate case data.</p></div>
  `,
})
export class CasesComponent implements OnInit {
  cases: any[] = [];
  query = '';
  riskFilter = 'all';
  actionFilter = 'all';

  constructor(private api: ApiService) {}

  ngOnInit(): void {
    this.api.cases().subscribe((r) => (this.cases = r.cases || []));
  }

  filteredCases(): any[] {
    const q = this.query.trim().toLowerCase();
    return this.cases.filter((c) => {
      const hay = `${c.case_id} ${c.title || ''} ${(c.techniques || []).join(' ')}`.toLowerCase();
      const textOk = !q || hay.includes(q);
      const riskOk = this.riskFilter === 'all' || this.severity(c.blast).toLowerCase() === this.riskFilter;
      const actionOk = this.actionFilter === 'all' || (this.actionFilter === 'pending' ? c.pending_actions > 0 : !c.pending_actions);
      return textOk && riskOk && actionOk;
    });
  }

  severity(blast: number): string {
    if (blast >= 70) return 'Critical';
    if (blast >= 50) return 'High';
    if (blast >= 30) return 'Medium';
    return 'Low';
  }
}
