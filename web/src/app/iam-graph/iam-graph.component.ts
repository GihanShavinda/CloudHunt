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
import { RouterLink } from '@angular/router';

import {
  forkJoin,
  of,
  switchMap,
} from 'rxjs';

import { ApiService } from '../api.service';
import {
  GraphRenderer,
} from '../graph-renderer.service';

@Component({
  selector: 'app-iam-graph',
  standalone: true,

  imports: [
    CommonModule,
    FormsModule,
    RouterLink,
  ],

  template: `
    <!-- =====================================================
         PAGE HEADER
         ===================================================== -->
    <div class="page-heading">

      <div>
        <div class="eyebrow">
          IDENTITY EXPOSURE
        </div>

        <h1>
          IAM Attack Graph
        </h1>

        <p>
          Explore AWS identities, roles,
          resources and privilege-escalation
          relationships discovered across
          CloudHunt cases.
        </p>
      </div>

      <div class="heading-actions">

        <span class="badge badge-success">
          {{ nodeCount }} nodes
        </span>

        <span class="badge badge-info">
          {{ edgeCount }} relationships
        </span>

        <span
          class="badge badge-danger"
          *ngIf="
            escalationCount > 0
          "
        >
          {{ escalationCount }}
          escalation edges
        </span>

      </div>

    </div>

    <!-- =====================================================
         GRAPH WORKSPACE
         ===================================================== -->
    <div class="graph-workspace">

      <!-- ===================================================
           MAIN GRAPH
           =================================================== -->
      <section
        class="
          panel
          graph-main
          panel-accent
        "
      >

        <div class="section-title-row">

          <div>

            <div class="eyebrow">
              GLOBAL IAM RELATIONSHIP GRAPH
            </div>

            <h2>
              Identity & Privilege Paths
            </h2>

          </div>

          <span
            class="
              badge
              badge-purple
            "
          >
            Interactive
          </span>

        </div>

        <!-- =================================================
             CONTROLS
             ================================================= -->
        <div class="graph-toolbar">

          <div
            class="
              search-field
              graph-search
            "
          >
            <span>⌕</span>

            <input
              [(ngModel)]="query"
              (ngModelChange)="
                render()
              "
              placeholder="
                Search IAM user,
                role or resource...
              "
            />
          </div>

          <select
            [(ngModel)]="
              typeFilter
            "
            (ngModelChange)="
              render()
            "
          >
            <option value="all">
              All node types
            </option>

            <option value="user">
              Users
            </option>

            <option value="principal">
              Principals
            </option>

            <option value="role">
              Roles
            </option>

            <option value="resource">
              Resources
            </option>

            <option value="policy">
              Policies
            </option>
          </select>

          <label
            class="
              toggle
              escalation-toggle
            "
          >
            <input
              type="checkbox"
              [(ngModel)]="
                escalationOnly
              "
              (ngModelChange)="
                render()
              "
            />

            <span>
              Escalation paths only
            </span>
          </label>

          <button
            class="
              secondary
              compact
            "
            (click)="
              resetFilters()
            "
          >
            Reset
          </button>

          <button
            class="
              secondary
              compact
            "
            (click)="
              fitGraph()
            "
          >
            Fit graph
          </button>

        </div>

        <!-- =================================================
             LEGEND
             ================================================= -->
        <div class="graph-legend">

          <span>
            <i
              class="
                legend-dot
                user
              "
            ></i>

            User / Principal
          </span>

          <span>
            <i
              class="
                legend-dot
                role
              "
            ></i>

            Role
          </span>

          <span>
            <i
              class="
                legend-dot
                resource
              "
            ></i>

            Resource
          </span>

          <span>
            <i
              class="
                legend-dot
                policy
              "
            ></i>

            Policy
          </span>

          <span>
            <i
              class="
                legend-line
                assume
              "
            ></i>

            AssumeRole / Observed
          </span>

          <span>
            <i
              class="
                legend-line
                escalate
              "
            ></i>

            Privilege escalation
          </span>

        </div>

        <!-- =================================================
             GRAPH
             ================================================= -->
        <div
          class="iam-graph-canvas"
        >
          <div
            #graph
            id="iam-cy"
          ></div>

          <div
            class="graph-empty-overlay"
            *ngIf="
              !filteredNodeCount
            "
          >
            <span>◎</span>

            <strong>
              No matching IAM nodes
            </strong>

            <p>
              Change the search or
              filters to display graph
              relationships.
            </p>
          </div>
        </div>

        <div class="graph-footer">

          <span class="muted small">
            Scroll to zoom · drag canvas
            to pan · click a node to inspect
          </span>

          <span class="muted small">
            Showing
            {{ filteredNodeCount }}
            node(s) and
            {{ filteredEdgeCount }}
            edge(s)
          </span>

        </div>

      </section>

      <!-- ===================================================
           INSPECTOR
           =================================================== -->
      <aside
        class="
          panel
          graph-inspector
        "
      >

        <div class="eyebrow">
          NODE INSPECTOR
        </div>

        <ng-container
          *ngIf="
            selectedNode;
            else graphHelp
          "
        >

          <div
            class="inspector-icon"
            [ngClass]="
              selectedNode.type ||
              'node'
            "
          >
            ◎
          </div>

          <h2>
            {{
              selectedNode.displayLabel ||
              selectedNode.label ||
              selectedNode.id
            }}
          </h2>

          <span
            class="
              badge
              badge-info
            "
          >
            {{
              selectedNode.type ||
              'node'
            }}
          </span>

          <div class="detail-list">

            <div>
              <span>
                Node ID
              </span>

              <strong
                class="
                  mono
                  break-text
                "
              >
                {{ selectedNode.id }}
              </strong>
            </div>

            <div
              *ngIf="
                selectedNode.arn
              "
            >
              <span>
                ARN
              </span>

              <strong
                class="
                  mono
                  break-text
                "
              >
                {{ selectedNode.arn }}
              </strong>
            </div>

            <div
              *ngIf="
                selectedNode.label
              "
            >
              <span>
                Original Label
              </span>

              <strong
                class="break-text"
              >
                {{
                  selectedNode.label
                }}
              </strong>
            </div>

            <div>
              <span>
                Related Cases
              </span>

              <strong>
                {{
                  selectedNode
                    .case_ids
                    ?.length || 0
                }}
              </strong>
            </div>

          </div>

          <div
            class="inspector-cases"
            *ngIf="
              selectedNode
                .case_ids
                ?.length
            "
          >

            <h3>
              Related Cases
            </h3>

            <a
              *ngFor="
                let id
                of selectedNode.case_ids
              "
              [routerLink]="[
                '/case',
                id
              ]"
              class="inspector-case"
            >
              <span>
                {{ id }}
              </span>

              <span>
                →
              </span>
            </a>

          </div>

        </ng-container>

        <ng-template #graphHelp>

          <div
            class="
              empty-state
              inspector-empty
            "
          >

            <span>
              ◎
            </span>

            <strong>
              Select a graph node
            </strong>

            <p>
              Click a principal, role,
              policy or resource to inspect
              its identity context and
              related cases.
            </p>

          </div>

        </ng-template>

      </aside>

    </div>

    <!-- =====================================================
         GRAPH STATISTICS
         ===================================================== -->
    <div class="iam-stats-grid">

      <div
        class="
          panel
          mini-stat
        "
      >
        <small>
          Principals
        </small>

        <strong>
          {{ principalCount }}
        </strong>

        <span class="muted small">
          IAM users and identities
        </span>
      </div>

      <div
        class="
          panel
          mini-stat
        "
      >
        <small>
          Roles
        </small>

        <strong>
          {{ roleCount }}
        </strong>

        <span class="muted small">
          Assumable IAM roles
        </span>
      </div>

      <div
        class="
          panel
          mini-stat
        "
      >
        <small>
          Resources
        </small>

        <strong>
          {{ resourceCount }}
        </strong>

        <span class="muted small">
          Reachable cloud resources
        </span>
      </div>

      <div
        class="
          panel
          mini-stat
          danger-stat
        "
      >
        <small>
          Escalation Edges
        </small>

        <strong>
          {{ escalationCount }}
        </strong>

        <span class="muted small">
          Privilege escalation paths
        </span>
      </div>

    </div>
  `,
})
export class IamGraphComponent
  implements
    OnInit,
    AfterViewInit,
    OnDestroy
{
  @ViewChild('graph')
  graphRef?: ElementRef<HTMLElement>;

  details: any[] = [];

  query = '';

  typeFilter = 'all';

  escalationOnly = false;

  selectedNode: any = null;

  nodeCount = 0;

  edgeCount = 0;

  principalCount = 0;

  roleCount = 0;

  resourceCount = 0;

  escalationCount = 0;

  filteredNodeCount = 0;

  filteredEdgeCount = 0;

  private cy: any;

  private viewReady = false;

  constructor(
    private api: ApiService,
    private renderer: GraphRenderer,
  ) {}

  ngOnInit(): void {

    this.api
      .cases()
      .pipe(
        switchMap((response) => {

          const cases =
            response?.cases || [];

          if (!cases.length) {
            return of<any[]>([]);
          }

          const requests =
            cases.map(
              (item: any) =>
                this.api.caseDetail(
                  item.case_id,
                ),
            );

          return forkJoin<any[]>(
            requests,
          );
        }),
      )
      .subscribe({
        next: (details) => {

          this.details =
            details || [];

          this.computeStats();

          this.render();
        },

        error: (error) => {

          console.error(
            'Unable to load IAM graph data',
            error,
          );

          this.details = [];

          this.computeStats();

          this.render();
        },
      });
  }

  ngAfterViewInit(): void {

    this.viewReady = true;

    this.render();
  }

  private aggregate():
    {
      nodes: any[];
      edges: any[];
    } {

    const nodeMap =
      new Map<string, any>();

    const edgeMap =
      new Map<string, any>();

    for (
      const detail
      of this.details
    ) {

      for (
        const node
        of detail.graph?.nodes || []
      ) {

        const data = {
          ...(node.data || node),
        };

        const id = data.id;

        if (!id) {
          continue;
        }

        const existing =
          nodeMap.get(id);

        if (existing) {

          existing.data.case_ids = [
            ...new Set([
              ...(existing
                .data
                .case_ids || []),

              detail.case_id,
            ]),
          ];

          continue;
        }

        nodeMap.set(
          id,
          {
            ...node,

            data: {
              ...data,

              case_ids: [
                detail.case_id,
              ],
            },
          },
        );
      }

      for (
        const edge
        of detail.graph?.edges || []
      ) {

        const data = {
          ...(edge.data || edge),
        };

        const key =
          data.id ||
          [
            data.source,
            data.target,
            data.kind ||
              data.label ||
              '',
          ].join('|');

        if (!edgeMap.has(key)) {
          edgeMap.set(
            key,
            {
              ...edge,
              data,
            },
          );
        }
      }
    }

    return {
      nodes: [
        ...nodeMap.values(),
      ],

      edges: [
        ...edgeMap.values(),
      ],
    };
  }

  private filteredGraph():
    {
      nodes: any[];
      edges: any[];
    } {

    const graph =
      this.aggregate();

    const query =
      this.query
        .trim()
        .toLowerCase();

    let nodes = [
      ...graph.nodes,
    ];

    let edges = [
      ...graph.edges,
    ];

    if (
      this.escalationOnly
    ) {

      edges =
        edges.filter(
          (edge) =>
            this.isEscalationEdge(
              edge,
            ),
        );

      const connectedIds =
        new Set<string>();

      for (
        const edge
        of edges
      ) {
        connectedIds.add(
          edge.data?.source,
        );

        connectedIds.add(
          edge.data?.target,
        );
      }

      nodes =
        nodes.filter(
          (node) =>
            connectedIds.has(
              node.data?.id,
            ),
        );
    }

    if (
      this.typeFilter !== 'all'
    ) {

      nodes =
        nodes.filter(
          (node) => {

            const type =
              (
                node.data?.type ||
                ''
              )
                .toLowerCase();

            if (
              this.typeFilter ===
              'resource'
            ) {
              return [
                'resource',
                's3',
              ].includes(type);
            }

            return (
              type ===
              this.typeFilter
            );
          },
        );

      const allowedIds =
        new Set(
          nodes.map(
            (node) =>
              node.data?.id,
          ),
        );

      edges =
        edges.filter(
          (edge) =>
            allowedIds.has(
              edge.data?.source,
            ) &&
            allowedIds.has(
              edge.data?.target,
            ),
        );
    }

    if (query) {

      const directMatches =
        nodes.filter(
          (node) => {

            const searchable =
              [
                node.data?.label,
                node.data?.id,
                node.data?.arn,
                node.data?.name,
              ]
                .filter(Boolean)
                .join(' ')
                .toLowerCase();

            return searchable
              .includes(query);
          },
        );

      const directIds =
        new Set(
          directMatches.map(
            (node) =>
              node.data?.id,
          ),
        );

      const visibleIds =
        new Set<string>(
          directIds,
        );

      for (
        const edge
        of edges
      ) {

        if (
          directIds.has(
            edge.data?.source,
          )
        ) {
          visibleIds.add(
            edge.data?.target,
          );
        }

        if (
          directIds.has(
            edge.data?.target,
          )
        ) {
          visibleIds.add(
            edge.data?.source,
          );
        }
      }

      nodes =
        nodes.filter(
          (node) =>
            visibleIds.has(
              node.data?.id,
            ),
        );

      const finalIds =
        new Set(
          nodes.map(
            (node) =>
              node.data?.id,
          ),
        );

      edges =
        edges.filter(
          (edge) =>
            finalIds.has(
              edge.data?.source,
            ) &&
            finalIds.has(
              edge.data?.target,
            ),
        );
    }

    return {
      nodes,
      edges,
    };
  }

  render(): void {

    if (
      !this.viewReady ||
      !this.graphRef
    ) {
      return;
    }

    const graph =
      this.filteredGraph();

    this.filteredNodeCount =
      graph.nodes.length;

    this.filteredEdgeCount =
      graph.edges.length;

    this.cy?.destroy?.();

    if (!graph.nodes.length) {
      this.cy = null;

      return;
    }

    this.cy =
      this.renderer.render(
        this.graphRef.nativeElement,
        graph,
        'cose',
      );

    this.cy.on(
      'tap',
      'node',
      (event: any) => {

        const data =
          event
            .target
            .data();

        this.selectedNode = {
          ...data,
        };
      },
    );

    this.cy.on(
      'tap',
      (event: any) => {

        if (
          event.target ===
          this.cy
        ) {
          this.selectedNode =
            null;
        }
      },
    );

    setTimeout(
      () => {

        this.cy?.resize();

        this.cy?.fit(
          undefined,
          85,
        );

        this.cy?.center();

      },
      80,
    );
  }

  fitGraph(): void {

    if (!this.cy) {
      return;
    }

    this.cy.resize();

    this.cy.fit(
      undefined,
      85,
    );

    this.cy.center();
  }

  resetFilters(): void {

    this.query = '';

    this.typeFilter = 'all';

    this.escalationOnly =
      false;

    this.selectedNode =
      null;

    this.render();
  }

  private computeStats(): void {

    const graph =
      this.aggregate();

    this.nodeCount =
      graph.nodes.length;

    this.edgeCount =
      graph.edges.length;

    this.principalCount =
      graph.nodes.filter(
        (node) =>
          [
            'principal',
            'user',
          ].includes(
            (
              node.data?.type ||
              ''
            )
              .toLowerCase(),
          ),
      ).length;

    this.roleCount =
      graph.nodes.filter(
        (node) =>
          (
            node.data?.type ||
            ''
          )
            .toLowerCase() ===
          'role',
      ).length;

    this.resourceCount =
      graph.nodes.filter(
        (node) =>
          [
            'resource',
            's3',
          ].includes(
            (
              node.data?.type ||
              ''
            )
              .toLowerCase(),
          ),
      ).length;

    this.escalationCount =
      graph.edges.filter(
        (edge) =>
          this.isEscalationEdge(
            edge,
          ),
      ).length;

    this.filteredNodeCount =
      graph.nodes.length;

    this.filteredEdgeCount =
      graph.edges.length;
  }

  private isEscalationEdge(
    edge: any,
  ): boolean {

    const kind =
      (
        edge.data?.kind ||
        ''
      )
        .toLowerCase();

    const label =
      (
        edge.data?.label ||
        ''
      )
        .toLowerCase();

    return (
      kind === 'escalation' ||
      kind ===
        'privilege_escalation' ||
      label.includes(
        'privilege escalation',
      ) ||
      label.includes(
        'privesc',
      )
    );
  }

  ngOnDestroy(): void {

    this.cy?.destroy?.();
  }
}