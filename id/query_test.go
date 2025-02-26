package id

import (
	"testing"
)

func TestSPIFFEID_Matches(t *testing.T) {
	type args struct {
		funcs []MatchFunc
	}
	tests := []struct {
		name    string
		id      *SPIFFEID
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Simple KV match",
			id:   MustParseID("spiffe://example.org/key1/value1/key2/value2"),
			args: args{
				funcs: []MatchFunc{
					Equals("key1", "value1"),
					Equals("key2", "value2"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple KV mismatch",
			id:   MustParseID("spiffe://example.org/key1/value1/key2/value2"),
			args: args{
				funcs: []MatchFunc{
					Equals("key1", "value1"),
					Equals("key2", "value3"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Simple OR",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					Equals("ns", "kube-system"),
					Or(Equals("deploy", "kube-dns"), Equals("deploy", "coredns")),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple OR mismatch",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					Equals("ns", "kube-system"),
					Or(Equals("deploy", "kube-dns"), Equals("deploy", "kube-proxy")),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Simple Glob",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					MatchGlob("deploy", "core*"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple Glob mismatch",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					MatchGlob("deploy", "kube*"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Simple isEmpty",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					IsEmpty("cluster"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple isEmpty mismatch",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					IsEmpty("ns"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Simple isNotEmpty",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					IsNotEmpty("ns"),
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple isNotEmpty mismatch",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					IsNotEmpty("cluster"),
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Simple Not",
			id:   MustParseID("spiffe://example.org/ns/kube-system/sa/default/deploy/coredns"),
			args: args{
				funcs: []MatchFunc{
					Not(IsEmpty("ns")),
				},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.id
			got, err := s.Matches(tt.args.funcs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("SPIFFEID.Matches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SPIFFEID.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}
