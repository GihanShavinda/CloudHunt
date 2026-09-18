import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { MobileApprovalComponent } from './mobile-approval.component';
import { ApiService } from './api.service';

const DETAIL = { case_id: 'case-1', recommended_actions: [{ action_key: 're-enable-logging', mode: 'human', status: 'pending', reasons: [] }] };

describe('MobileApprovalComponent', () => {
  let fixture: ComponentFixture<MobileApprovalComponent>;
  const api = {
    caseDetail: jasmine.createSpy('caseDetail').and.returnValue(of(DETAIL)),
    caseSummary: jasmine.createSpy('caseSummary').and.returnValue(of({ summary: 'grounded', source: 'template', rejected: false })),
    registerDevice: jasmine.createSpy('registerDevice').and.returnValue(of({ device_id: 'dev-1' })),
    issueApprovalToken: jasmine.createSpy('issueApprovalToken').and.returnValue(of({ token: 'one-time' })),
    mobileDecision: jasmine.createSpy('mobileDecision').and.returnValue(of({ status: 'executed' })),
  };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MobileApprovalComponent],
      providers: [provideHttpClient(), { provide: ApiService, useValue: api },
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id: 'case-1' }) } } }],
    }).compileComponents();
    fixture = TestBed.createComponent(MobileApprovalComponent);
  });

  it('uses the same case action approval endpoint service path with mobile token/TOTP', () => {
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    cmp.totp['re-enable-logging'] = '123456';
    cmp.decide('re-enable-logging', 'approve');
    expect(api.issueApprovalToken).toHaveBeenCalledWith('case-1', 're-enable-logging');
    expect(api.mobileDecision).toHaveBeenCalledWith('case-1', 're-enable-logging', '123456', 'one-time', 'approve');
  });
});
