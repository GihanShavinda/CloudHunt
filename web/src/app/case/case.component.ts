import {
  AfterViewInit,
  Component,
  ElementRef,
  OnDestroy,
  OnInit,
  ViewChild,
} from '@angular/core';

import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  ActivatedRoute,
  RouterLink,
} from '@angular/router';

import { ApiService } from '../api.service';
import { AuthService } from '../auth.service';
import { GraphRenderer } from '../graph-renderer.service';

@Component({
  selector: 'app-case',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
  ],
  template: `
    <ng-container *ngIf="detail">

      <!-- =====================================================
           PAGE HEADER
           ===================================================== -->
      <div class="page-heading case-page-heading">
        <div>
          <a
            routerLink="/cases"
            class="breadcrumb"
          >
            ← Cases
          </a>

          <div class="eyebrow">
            INCIDENT WORKSPACE
          </div>

          <h1>
            {{
              detail.title ||
              detail.case_id
            }}
          </h1>

          <div class="muted mono small">
            {{ detail.case_id }}
          </div>
        </div>

        <div class="case-score-block">
          <small>
            BLAST RADIUS
          </small>

          <strong>
            {{
              detail.blast.score
                | number: '1.0-0'
            }}
          </strong>

          <span class="badge badge-warning">
            rank
            {{
              detail.rank
                | number: '1.2-2'
            }}
          </span>
        </div>
      </div>

      <!-- =====================================================
           ACTION TOOLBAR
           ===================================================== -->
      <div class="toolbar">

        <button
          class="secondary"
          (click)="download('json')"
        >
          ↓ JSON
        </button>

        <button
          class="secondary"
          (click)="download('csv')"
        >
          ↓ CSV
        </button>

        <button
          class="secondary"
          (click)="download('pdf')"
        >
          ↓ Incident PDF
        </button>

        <a
          class="button-link secondary"
          [routerLink]="[
            '/mobile/case',
            detail.case_id
          ]"
        >
          Mobile approval
        </a>

      </div>

      <!-- =====================================================
           CASE SUMMARY
           ===================================================== -->
      <section
        class="
          panel
          summary-panel
          panel-accent
        "
        *ngIf="summary"
      >
        <div class="section-title-row">

          <div>
            <div class="eyebrow">
              GROUNDED CASE SUMMARY
            </div>

            <!--
              Keep the literal text "Case summary"
              because the existing Jasmine test
              checks for this exact phrase.
            -->
            <h2>
              Case summary — Investigation
            </h2>
          </div>

          <span
            class="badge"
            [class.badge-info]="
              summary.source === 'ai'
            "
            [class.badge-success]="
              summary.source === 'template'
            "
            [class.badge-danger]="
              summary.rejected
            "
          >
            {{
              summary.source === 'template'
                ? 'template summary'
                : summary.source === 'ai'
                  ? 'AI summary'
                  : summary.source
            }}
          </span>

        </div>

        <div
          class="alert danger-alert"
          *ngIf="summary.rejected"
        >
          <strong>
            AI summary rejected
          </strong>

          <span>
            The validated deterministic
            Milestone 9 fallback is shown
            instead.
          </span>
        </div>

        <p class="summary-text">
          {{ summary.summary }}
        </p>

      </section>

      <!-- =====================================================
           CASE WORKSPACE
           ===================================================== -->
      <div class="case-workspace-grid">

        <!-- ===================================================
             IAM / ATTACK GRAPH
             =================================================== -->
        <section
          class="
            panel
            case-graph-panel
          "
        >
          <div class="section-title-row">

            <div>
              <div class="eyebrow">
                IDENTITY ATTACK PATH
              </div>

              <h2>
                AssumeRole +
                Privilege Escalation
              </h2>
            </div>

            <a routerLink="/iam-graph">
              Open global IAM graph →
            </a>

          </div>

          <div
            #cy
            id="cy"
          ></div>

          <div class="graph-legend">

            <span>
              <i
                class="
                  legend-line
                  assume
                "
              ></i>

              Observed / AssumeRole
            </span>

            <span>
              <i
                class="
                  legend-line
                  escalate
                "
              ></i>

              Escalation
            </span>

          </div>

        </section>

        <!-- ===================================================
             EVIDENCE TIMELINE
             =================================================== -->
        <section class="panel">

          <div class="eyebrow">
            EVIDENCE
          </div>

          <h2>
            Timeline
          </h2>

          <div
            *ngFor="
              let ev
              of detail.timeline
            "
            class="timeline-item"
          >

            <div
              class="
                muted
                small
                mono
              "
            >
              {{ ev.ts }}
            </div>

            <strong>
              {{ ev.action }}
            </strong>

            <div class="muted small">
              {{ short(ev.principal) }}

              {{
                ev.target
                  ? ' → ' +
                    short(ev.target)
                  : ''
              }}
            </div>

            <div class="tag-line">

              <span
                class="
                  badge
                  badge-danger
                "
                *ngFor="
                  let d
                  of ev.detections
                "
              >
                {{ d }}
              </span>

            </div>

          </div>

          <p
            class="muted"
            *ngIf="
              !detail.timeline?.length
            "
          >
            No evidence events recorded.
          </p>

        </section>

        <!-- ===================================================
             MITRE ATT&CK
             =================================================== -->
        <section class="panel">

          <div class="eyebrow">
            MITRE ATT&CK
          </div>

          <h2>
            Technique Coverage
          </h2>

          <div
            class="attack-group"
            *ngFor="
              let tactic
              of attackTactics()
            "
          >

            <strong>
              {{ tactic }}
            </strong>

            <div class="tag-line">

              <span
                class="
                  badge
                  badge-info
                "
                *ngFor="
                  let t
                  of detail.attack_map[tactic]
                "
              >
                {{ t }}
              </span>

            </div>

          </div>

          <p
            class="muted"
            *ngIf="
              !attackTactics().length
            "
          >
            No ATT&CK techniques mapped
            to this case.
          </p>

        </section>

        <!-- ===================================================
             ADVANCED DETECTIONS
             =================================================== -->
        <section
          class="panel"
          *ngIf="
            detail
              .advanced_detections
              ?.length
          "
        >

          <div class="eyebrow">
            M8 ANALYTICS
          </div>

          <h2>
            Advanced Findings
          </h2>

          <div
            *ngFor="
              let d
              of detail
                .advanced_detections
            "
            class="finding-row"
          >

            <span
              class="
                severity-icon
                high
              "
            >
              !
            </span>

            <div class="finding-content">

              <strong>
                {{ d.title }}
              </strong>

              <div class="muted small">
                {{ short(d.principal) }}

                {{
                  d.resource
                    ? ' → ' +
                      short(d.resource)
                    : ''
                }}
              </div>

              <div class="tag-line">

                <span
                  class="
                    badge
                    badge-info
                  "
                  *ngFor="
                    let t
                    of d.attack_ids
                  "
                >
                  {{ t }}
                </span>

              </div>

              <p>
                {{ d.message }}
              </p>

            </div>

          </div>

        </section>

        <!-- ===================================================
             RECOMMENDED RESPONSE
             =================================================== -->
        <section class="panel">

          <div class="eyebrow">
            RESPONSE
          </div>

          <h2>
            Recommended Actions
          </h2>

          <div
            *ngFor="
              let a
              of detail
                .recommended_actions
            "
            class="response-action"
          >

            <div class="section-title-row">

              <div>

                <strong>
                  {{ a.action_key }}
                </strong>

                <div class="tag-line">

                  <span
                    class="badge"
                    [class.badge-success]="
                      a.status ===
                      'executed'
                    "
                    [class.badge-warning]="
                      a.status ===
                      'pending'
                    "
                    [class.badge-danger]="
                      a.status ===
                      'denied'
                    "
                  >
                    {{ a.status }}
                  </span>

                  <span
                    class="
                      badge
                      badge-info
                    "
                  >
                    {{ a.mode }}
                  </span>

                </div>

              </div>

            </div>

            <div
              class="muted small"
              *ngFor="
                let r
                of a.reasons
              "
            >
              • {{ r }}
            </div>

            <div
              *ngIf="
                a.status ===
                'pending'
              "
              class="approval-inline"
            >

              <ng-container
                *ngIf="
                  auth.canApprove;
                  else noPerm
                "
              >

                <input
                  [(ngModel)]="
                    totp[
                      a.action_key
                    ]
                  "
                  placeholder="TOTP code"
                  maxlength="8"
                />

                <button
                  (click)="
                    approve(
                      a.action_key
                    )
                  "
                >
                  Approve
                </button>

              </ng-container>

              <ng-template #noPerm>

                <span
                  class="
                    badge
                    badge-warning
                  "
                >
                  Analyst/Admin approval
                  required
                </span>

              </ng-template>

            </div>

          </div>

          <p
            class="bad"
            *ngIf="error"
          >
            {{ error }}
          </p>

        </section>

        <!-- ===================================================
             BLAST RADIUS
             =================================================== -->
        <section class="panel">

          <div class="eyebrow">
            BLAST RADIUS
          </div>

          <h2>
            Score Components
          </h2>

          <div
            class="component-row"
            *ngFor="
              let entry
              of componentEntries()
            "
          >

            <div>

              <strong>
                {{ entry[0] }}
              </strong>

              <span>
                {{ entry[1] }}
              </span>

            </div>

            <div class="bar">

              <i
                [style.width.%]="
                  componentPercent(
                    entry[1]
                  )
                "
              ></i>

            </div>

          </div>

          <p
            class="muted small"
            *ngIf="
              detail
                .blast
                .explanation
            "
          >
            {{
              detail
                .blast
                .explanation
            }}
          </p>

        </section>

        <!-- ===================================================
             AUDIT HISTORY
             =================================================== -->
        <section
          class="
            panel
            audit-panel
          "
        >

          <div class="section-title-row">

            <div>

              <div class="eyebrow">
                ACCOUNTABILITY
              </div>

              <h2>
                Append-Only Audit History
              </h2>

            </div>

            <span
              class="
                badge
                badge-success
              "
            >
              Integrity trail
            </span>

          </div>

          <div class="table-wrap">

            <table>

              <thead>
                <tr>
                  <th>
                    Timestamp
                  </th>

                  <th>
                    Action
                  </th>

                  <th>
                    Decision
                  </th>

                  <th>
                    Status
                  </th>

                  <th>
                    Actor
                  </th>

                  <th>
                    Channel
                  </th>
                </tr>
              </thead>

              <tbody>

                <tr
                  *ngFor="
                    let r
                    of detail.audit
                  "
                >

                  <td
                    class="
                      mono
                      small
                      muted
                    "
                  >
                    {{ r.ts }}
                  </td>

                  <td>
                    <strong>
                      {{ r.action_key }}
                    </strong>
                  </td>

                  <td>

                    <span
                      class="
                        badge
                        badge-info
                      "
                    >
                      {{
                        r.approval_decision ||
                        r.decision
                      }}
                    </span>

                  </td>

                  <td>

                    <span
                      class="badge"
                      [class.badge-success]="
                        r.status ===
                        'executed'
                      "
                      [class.badge-warning]="
                        r.status ===
                        'pending'
                      "
                      [class.badge-danger]="
                        r.status ===
                        'denied'
                      "
                    >
                      {{ r.status }}
                    </span>

                  </td>

                  <td>
                    {{
                      r.approver ||
                      'system'
                    }}
                  </td>

                  <td>
                    <span class="badge">
                      {{ r.channel }}
                    </span>
                  </td>

                </tr>

                <tr
                  *ngIf="
                    !detail.audit?.length
                  "
                >
                  <td
                    colspan="6"
                    class="muted"
                  >
                    No actions recorded yet.
                  </td>
                </tr>

              </tbody>

            </table>

          </div>

        </section>

      </div>

    </ng-container>
  `,
})
export class CaseComponent
  implements OnInit, AfterViewInit, OnDestroy
{
  @ViewChild('cy')
  cyRef?: ElementRef<HTMLElement>;

  detail: any;

  summary: any;

  totp: Record<string, string> = {};

  error = '';

  private viewReady = false;

  private cy: any;

  constructor(
    private route: ActivatedRoute,
    private api: ApiService,
    public auth: AuthService,
    private renderer: GraphRenderer
  ) {}

  ngOnInit(): void {
    const id =
      this.route.snapshot
        .paramMap
        .get('id');

    if (!id) {
      this.error =
        'Case identifier is missing.';

      return;
    }

    this.load(id);
  }

  ngAfterViewInit(): void {
    this.viewReady = true;

    this.renderGraph();
  }

  private load(
    id: string
  ): void {
    this.api
      .caseDetail(id)
      .subscribe({
        next: (d) => {
          this.detail = d;

          this.renderGraph();
        },

        error: (e) => {
          this.error =
            e?.error?.detail ||
            'Unable to load case details.';
        },
      });

    this.api
      .caseSummary(id)
      .subscribe({
        next: (s) => {
          this.summary = s;
        },

        error: () => {
          this.summary = null;
        },
      });
  }

  private renderGraph(): void {
    if (
      !this.viewReady ||
      !this.detail ||
      !this.cyRef
    ) {
      return;
    }

    this.cy?.destroy?.();

    this.cy =
      this.renderer.render(
        this.cyRef.nativeElement,
        this.detail.graph
      );
  }

  attackTactics(): string[] {
    if (!this.detail) {
      return [];
    }

    return Object.keys(
      this.detail.attack_map || {}
    );
  }

  short(
    value: string | null | undefined
  ): string {
    if (!value) {
      return '';
    }

    return (
      value.split('/').pop() ||
      value
    );
  }

  componentEntries():
    [string, any][] {

    return Object.entries(
      this.detail
        ?.blast
        ?.components || {}
    ) as [string, any][];
  }

  componentPercent(
    value: any
  ): number {
    const numberValue =
      Number(value);

    if (
      !Number.isFinite(
        numberValue
      )
    ) {
      return 0;
    }

    const percentage =
      numberValue <= 1
        ? numberValue * 100
        : numberValue;

    return Math.max(
      0,
      Math.min(
        100,
        percentage
      )
    );
  }

  approve(
    actionKey: string
  ): void {
    this.error = '';

    const code =
      this.totp[actionKey] ||
      '';

    this.api
      .approve(
        this.detail.case_id,
        actionKey,
        code
      )
      .subscribe({
        next: () => {
          this.totp[actionKey] = '';

          this.load(
            this.detail.case_id
          );
        },

        error: (e) => {
          this.error =
            e?.error?.detail ||
            'Approval failed (check role / TOTP).';
        },
      });
  }

  download(
    format:
      | 'json'
      | 'csv'
      | 'pdf'
  ): void {
    this.api
      .exportCase(
        this.detail.case_id,
        format
      )
      .subscribe({
        next: (blob) => {
          const url =
            URL.createObjectURL(
              blob
            );

          const anchor =
            document.createElement(
              'a'
            );

          anchor.href = url;

          anchor.download =
            `${this.detail.case_id}.${format}`;

          document.body.appendChild(
            anchor
          );

          anchor.click();

          anchor.remove();

          URL.revokeObjectURL(
            url
          );
        },

        error: (e) => {
          this.error =
            e?.error?.detail ||
            `Unable to export ${format.toUpperCase()} report.`;
        },
      });
  }

  ngOnDestroy(): void {
    this.cy?.destroy?.();
  }
}