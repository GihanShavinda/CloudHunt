"""Wildcard matching primitives — the foundation every decision rests on."""

from __future__ import annotations

from cloudhunt.graph.matching import (
    action_matches,
    any_action_matches,
    any_resource_matches,
    resource_matches,
)


def test_action_wildcards():
    assert action_matches("*", "s3:GetObject")
    assert action_matches("s3:*", "s3:GetObject")
    assert action_matches("s3:Get*", "s3:GetObject")
    assert not action_matches("s3:Get*", "s3:PutObject")
    assert not action_matches("s3:*", "iam:CreatePolicyVersion")


def test_action_matching_is_case_insensitive():
    # IAM treats action names case-insensitively.
    assert action_matches("s3:getobject", "s3:GetObject")
    assert action_matches("S3:GetObject", "s3:getobject")


def test_resource_wildcards_are_case_sensitive():
    assert resource_matches("*", "arn:aws:s3:::anything")
    assert resource_matches("arn:aws:s3:::b/*", "arn:aws:s3:::b/key.csv")
    assert not resource_matches("arn:aws:s3:::b/*", "arn:aws:s3:::b")  # no slash -> no match
    assert not resource_matches("arn:aws:s3:::B/*", "arn:aws:s3:::b/key.csv")  # case matters


def test_question_mark_matches_single_char():
    assert resource_matches("arn:aws:s3:::b/2024-0?", "arn:aws:s3:::b/2024-09")
    assert not resource_matches("arn:aws:s3:::b/2024-0?", "arn:aws:s3:::b/2024-099")


def test_any_helpers_accept_string_or_list():
    assert any_action_matches("s3:*", "s3:GetObject")
    assert any_action_matches(["iam:*", "s3:Get*"], "s3:GetObject")
    assert not any_resource_matches(["arn:aws:s3:::x", "arn:aws:s3:::y"], "arn:aws:s3:::z")
