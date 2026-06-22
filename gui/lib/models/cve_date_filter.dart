enum CveDateField { published, modified, latest }

class CveDateFilter {
  final DateTime? after;
  final DateTime? before;
  final CveDateField field;
  final bool includeUndated;

  const CveDateFilter({
    this.after,
    this.before,
    this.field = CveDateField.published,
    this.includeUndated = false,
  });

  static const CveDateFilter empty = CveDateFilter();

  bool get hasConstraints => after != null || before != null;

  // Returns true if the CVE with the given dates passes this filter.
  bool matches(DateTime? published, DateTime? modified) {
    if (!hasConstraints) return true;

    final date = switch (field) {
      CveDateField.published => published,
      CveDateField.modified => modified,
      CveDateField.latest => _latest(published, modified),
    };

    if (date == null) return includeUndated;
    if (after != null && date.isBefore(after!)) return false;
    if (before != null && date.isAfter(before!)) return false;
    return true;
  }

  static DateTime? _latest(DateTime? a, DateTime? b) {
    if (a == null) return b;
    if (b == null) return a;
    return b.isAfter(a) ? b : a;
  }

  CveDateFilter copyWith({
    Object? after = _sentinel,
    Object? before = _sentinel,
    CveDateField? field,
    bool? includeUndated,
  }) =>
      CveDateFilter(
        after: after == _sentinel ? this.after : after as DateTime?,
        before: before == _sentinel ? this.before : before as DateTime?,
        field: field ?? this.field,
        includeUndated: includeUndated ?? this.includeUndated,
      );

  static const Object _sentinel = Object();
}
