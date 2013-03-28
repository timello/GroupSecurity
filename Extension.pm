# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# This Source Code Form is "Incompatible With Secondary Licenses", as
# defined by the Mozilla Public License, v. 2.0.

package Bugzilla::Extension::GroupSecurity;

use 5.10.1;
use strict;
use parent qw(Bugzilla::Extension);

our $VERSION = '0.01';

use Bugzilla::Error qw(ThrowUserError);
use Bugzilla::Product;


BEGIN {
    no warnings 'redefine';
    *Bugzilla::User::_orig_in_group = \&Bugzilla::User::in_group;
    *Bugzilla::User::in_group = \&_user_in_group;
    *Bugzilla::User::check_can_admin_product = \&_user_check_can_admin_product;
}

sub _user_in_group {
    my ($self, $group, $product_id) = @_;
    # If this user is an admin of at least one product/group,
    # we grant him access to the editcomponents group and
    # revoke access later in the check_can_admin_product.

    if ($group eq 'editcomponents') {
        return 1 if scalar @{ $self->bless_groups };
    }
    return $self->_orig_in_group($group, $product_id);
}

sub _user_check_can_admin_product {
    my ($self, $product_name, $params) = @_;

    # First make sure the product name is valid.
    my $product = Bugzilla::Product->check(
        {   name               => $product_name,
            allow_inaccessible => 1
        }
    );

    my @groups = keys %{ $product->group_controls || {} };

    # In case the product does not contain any group
    # control only Bugzilla admin can edit it.
    if (!@groups) {
        return $product if $self->in_group('admin');
        return 0;
    }

    my $can_bless = 1;
    foreach my $group_id (@groups) {
        # The user must be admin of all control groups;
        if (!$self->can_bless($group_id)) {
            $can_bless = 0;
            last;
        }
    }

    return $product if $can_bless;

    return 0 if $params->{skip_error} == 1;
    
    # The group/product admin can edit only products he is
    # admin of.
    ThrowUserError('product_admin_denied', { product => $product->name });
}

sub template_before_process {
    my ($self, $args) = @_;
    my ($vars, $file, $context) = @$args{qw(vars file context)};

    my $user = Bugzilla->user;

    if ($file =~ m{admin/( # Either:
                          (components|versions|milestones)/ # has this:
                           select-product.html.tmpl | # template or:
                          products/list.html.tmpl
                         )
                       }x)
    {
        if (!$user->in_group('admin')) {
            my @products;
            foreach my $product (Bugzilla::Product->get_all()) {
                my $can_admin_product =
                    $user->check_can_admin_product($product->name,
                                                   { skip_error => 1 });

                push @products, $product if $can_admin_product;
            }
            $vars->{products} = \@products;
        }
    }
}

__PACKAGE__->NAME;
