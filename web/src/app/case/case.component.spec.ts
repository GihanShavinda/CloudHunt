import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { of } from 'rxjs';

import { CaseComponent } from './case.component';
import { ApiService } from '../api.service';
import { AuthService } from '../auth.service';
import { GraphRenderer } from '../graph-renderer.service';

/** A seeded case-detail fixture shaped exactly like the API response. */
const FIXTURE = {
  case_id: 'case-1',
  title: 'Leaked ci-bot key → privilege escalation',
  rank: 0.672,
  blast: { score: 46, components: {}, explanation: '' },
  chain: [
    { order: 1, actor: 'arn:aws:iam::1:user/ci-bot', action: 'AssumeRole',
      tactic: 'Privilege Escalation', attack_id: 'T1548', target: 'arn:aws:iam::1:role/deploy' },
  ],
  graph: {
    nodes: [
      { data: { id: 'arn:aws:iam::1:user/ci-bot', label: 'ci-bot', type: 'user' } },
      { data: { id: 'arn:aws:iam::1:role/deploy', label: 'deploy', type: 'role' } },
      { data: { id: 'arn:aws:s3:::acme-crown-jewels', label: 'acme-crown-jewels', type: 'resource' } },
    ],
    edges: [
      { data: { id: 'a0', source: 'arn:aws:iam::1:user/ci-bot',
                target: 'arn:aws:iam::1:role/deploy', label: 'AssumeRole', kind: 'activity' } },
      { data: { id: 'e0', source: 'arn:aws:iam::1:role/deploy',
                target: 'arn:aws:s3:::acme-crown-jewels', label: 'CreatePolicyVersion', kind: 'escalation' } },
    ],
  },
  timeline: [
    { ts: '2026-09-10T03:01:00+00:00', principal: 'ci-bot', action: 'AssumeRole',
      target: 'arn:aws:iam::1:role/deploy', detections: ['new-geo'] },
  ],
  attack_map: { 'Privilege Escalation': ['T1098.003'], 'Defense Evasion': ['T1562.008'] },
  recommended_actions: [
    { action_key: 'deactivate-access-key', mode: 'auto', status: 'executed', reasons: ['auto'] },
    { action_key: 're-enable-logging', mode: 'human', status: 'pending', reasons: ['always human'] },
  ],
  audit: [
    { ts: '2026-09-10T03:07:00+00:00', action_key: 'deactivate-access-key',
      decision: 'auto', status: 'executed', approver: null },
  ],
};

/** Fake renderer records what it was asked to draw — no cytoscape/DOM needed. */
class FakeRenderer {
  lastContainer: HTMLElement | null = null;
  lastElements: any = null;
  render(container: HTMLElement, elements: any) {
    this.lastContainer = container;
    this.lastElements = elements;
    return { destroy() {} };
  }
}

describe('CaseComponent (workspace graph render)', () => {
  let fixture: ComponentFixture<CaseComponent>;
  let renderer: FakeRenderer;
  let auth: AuthService;
  const api = { caseDetail: () => of(FIXTURE), caseSummary: jasmine.createSpy('caseSummary').and.returnValue(of({ summary: 'template summary', source: 'template', valid: true, rejected: false, violations: [] })), exportCase: jasmine.createSpy('exportCase').and.returnValue(of(new Blob(['x']))), approve: jasmine.createSpy('approve').and.returnValue(of({})) };

  beforeEach(async () => {
    renderer = new FakeRenderer();
    await TestBed.configureTestingModule({
      imports: [CaseComponent],
      providers: [
        provideHttpClient(),
        { provide: ApiService, useValue: api },
        { provide: GraphRenderer, useValue: renderer },
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id: 'case-1' }) } } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(CaseComponent);
    auth = TestBed.inject(AuthService);
  });

  it('renders the server-provided graph elements into the renderer', () => {
    fixture.detectChanges(); // ngOnInit (loads fixture) + ngAfterViewInit (renders)
    // The component draws exactly what the API returned — no client-side transform.
    expect(renderer.lastElements).toBe(FIXTURE.graph);
    expect(renderer.lastElements.nodes.length).toBe(3);
    expect(renderer.lastElements.edges.length).toBe(2);
    expect(renderer.lastContainer).toBeTruthy(); // #cy element existed
  });

  it('shows the ATT&CK tactics and timeline the API computed', () => {
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent || '';
    expect(text).toContain('Privilege Escalation');
    expect(text).toContain('T1098.003');
    expect(text).toContain('AssumeRole');
  });

  it('shows deterministic/AI summary status returned by the backend', () => {
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent || '';
    expect(text).toContain('Case summary');
    expect(text).toContain('template summary');
  });

  it('shows a visible rejection status while rendering the safe fallback', () => {
    api.caseSummary.and.returnValue(of({ summary: 'safe fallback', source: 'template', valid: false, rejected: true, violations: ['unsupported_entity'] }));
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent || '';
    expect(text).toContain('AI summary rejected');
    expect(text).toContain('safe fallback');
  });

  it('RBAC: a viewer cannot approve; an analyst can', () => {
    auth.user = { username: 'viewer', role: 'viewer' };
    expect(auth.canApprove).toBeFalse();
    auth.user = { username: 'analyst', role: 'cloud_analyst' };
    expect(auth.canApprove).toBeTrue();
  });

  it('approve() posts the TOTP code through the API', () => {
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    cmp.totp['re-enable-logging'] = '123456';
    cmp.approve('re-enable-logging');
    expect(api.approve).toHaveBeenCalledWith('case-1', 're-enable-logging', '123456');
  });
});
