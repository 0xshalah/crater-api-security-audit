<?php

namespace Database\Seeders;

use Crater\Models\Company;
use Crater\Models\Customer;
use Crater\Models\Estimate;
use Crater\Models\Expense;
use Crater\Models\ExpenseCategory;
use Crater\Models\Invoice;
use Crater\Models\Item;
use Crater\Models\Note;
use Crater\Models\Payment;
use Crater\Models\PaymentMethod;
use Crater\Models\RecurringInvoice;
use Crater\Models\User;
use Illuminate\Database\Seeder;
use Silber\Bouncer\BouncerFacade;
use Vinkla\Hashids\Facades\Hashids;

class SecurityResearchSeeder extends Seeder
{
    /**
     * Run the research fixtures seed idempotently.
     *
     * @return void
     */
    public function run()
    {
        // 1. Sandbox configuration: disable external network side-effects
        config([
            'mail.driver' => 'array',
            'filesystems.default' => 'local',
            'backup.backup.destination.disks' => ['local'],
        ]);

        // 2. Seed base currencies and countries prerequisite tables
        $this->call([
            CurrenciesTableSeeder::class,
            CountriesTableSeeder::class,
        ]);

        // 3. Setup Company A (Tenant Alpha) & Owner A
        $ownerA = User::firstOrCreate(['email' => 'owner.a@crater.test'], [
            'name' => 'Owner Alpha',
            'password' => 'Password123!',
            'role' => 'super admin'
        ]);

        $companyA = Company::firstOrCreate(['slug' => 'company-alpha'], [
            'name' => 'Company Alpha',
            'owner_id' => $ownerA->id
        ]);
        if (! $companyA->unique_hash) {
            $companyA->unique_hash = Hashids::connection(Company::class)->encode($companyA->id);
            $companyA->save();
            $companyA->setupDefaultData();
            $ownerA->companies()->syncWithoutDetaching([$companyA->id]);
        }
        BouncerFacade::scope()->to($companyA->id);
        $ownerA->assign('super admin');

        // 4. Setup Company B (Tenant Beta) & Owner B
        $ownerB = User::firstOrCreate(['email' => 'owner.b@crater.test'], [
            'name' => 'Owner Beta',
            'password' => 'Password123!',
            'role' => 'super admin'
        ]);

        $companyB = Company::firstOrCreate(['slug' => 'company-beta'], [
            'name' => 'Company Beta',
            'owner_id' => $ownerB->id
        ]);
        if (! $companyB->unique_hash) {
            $companyB->unique_hash = Hashids::connection(Company::class)->encode($companyB->id);
            $companyB->save();
            $companyB->setupDefaultData();
            $ownerB->companies()->syncWithoutDetaching([$companyB->id]);
        }
        BouncerFacade::scope()->to($companyB->id);
        $ownerB->assign('super admin');

        // 5. Setup User A & User B (Abilities Setara pada Tenant Masing-Masing)
        $userA = User::firstOrCreate(['email' => 'user.a@crater.test'], [
            'name' => 'User Alpha',
            'password' => 'Password123!',
            'role' => 'user'
        ]);
        $companyA->users()->syncWithoutDetaching([$userA->id]);

        $userB = User::firstOrCreate(['email' => 'user.b@crater.test'], [
            'name' => 'User Beta',
            'password' => 'Password123!',
            'role' => 'user'
        ]);
        $companyB->users()->syncWithoutDetaching([$userB->id]);

        $standardAbilities = [
            'view-customer', 'create-customer', 'edit-customer', 'delete-customer',
            'view-item', 'create-item', 'edit-item', 'delete-item',
            'view-invoice', 'create-invoice', 'edit-invoice', 'delete-invoice', 'send-invoice',
            'view-estimate', 'create-estimate', 'edit-estimate', 'delete-estimate', 'send-estimate',
            'view-expense', 'create-expense', 'edit-expense', 'delete-expense',
            'view-payment', 'create-payment', 'edit-payment', 'delete-payment', 'send-payment',
            'view-recurring-invoice', 'create-recurring-invoice', 'edit-recurring-invoice', 'delete-recurring-invoice',
            'view-all-notes', 'manage-all-notes',
        ];

        $configAbilities = collect(config('abilities.abilities'))->keyBy('ability');

        // Assign abilities to User A under Tenant A
        BouncerFacade::scope()->to($companyA->id);
        $roleStaffA = BouncerFacade::role()->firstOrCreate(['name' => 'researcher', 'scope' => $companyA->id]);
        foreach ($standardAbilities as $ability) {
            $model = $configAbilities->get($ability)['model'] ?? null;
            if ($model) {
                BouncerFacade::allow($roleStaffA)->to($ability, $model);
            } else {
                BouncerFacade::allow($roleStaffA)->to($ability);
            }
        }
        $userA->assign($roleStaffA);

        // Assign identical abilities to User B under Tenant B
        BouncerFacade::scope()->to($companyB->id);
        $roleStaffB = BouncerFacade::role()->firstOrCreate(['name' => 'researcher', 'scope' => $companyB->id]);
        foreach ($standardAbilities as $ability) {
            $model = $configAbilities->get($ability)['model'] ?? null;
            if ($model) {
                BouncerFacade::allow($roleStaffB)->to($ability, $model);
            } else {
                BouncerFacade::allow($roleStaffB)->to($ability);
            }
        }
        $userB->assign($roleStaffB);

        // 6. Setup User Low (Tenant A, Hanya Memiliki Ability view-invoice)
        $userLow = User::firstOrCreate(['email' => 'user.low@crater.test'], [
            'name' => 'User Low Privilege',
            'password' => 'Password123!',
            'role' => 'user'
        ]);
        $companyA->users()->syncWithoutDetaching([$userLow->id]);
        BouncerFacade::scope()->to($companyA->id);
        $roleLow = BouncerFacade::role()->firstOrCreate(['name' => 'auditor-low', 'scope' => $companyA->id]);
        BouncerFacade::allow($roleLow)->to('view-invoice', Invoice::class);
        $userLow->assign($roleLow);

        // 7. Data Sintetis Berpasangan (Company A vs Company B)
        $this->seedTenantData($companyA, $ownerA);
        $this->seedTenantData($companyB, $ownerB);
    }

    private function seedTenantData(Company $company, User $creator)
    {
        $prefix = strtoupper(substr($company->slug, -1)); // 'A' atau 'B'

        for ($i = 1; $i <= 2; $i++) {
            $customer = Customer::firstOrCreate([
                'name' => "Customer {$prefix} {$i}",
                'company_id' => $company->id,
            ], [
                'email' => "customer.{$prefix}.{$i}@crater.test",
                'currency_id' => 1,
            ]);

            $item = Item::firstOrCreate([
                'name' => "Item {$prefix} {$i}",
                'company_id' => $company->id
            ], [
                'price' => 100000 * $i,
            ]);

            $invoice = Invoice::firstOrCreate([
                'invoice_number' => "INV-{$prefix}-00{$i}",
                'company_id' => $company->id
            ], [
                'customer_id' => $customer->id,
                'invoice_date' => now(),
                'due_date' => now()->addDays(30),
                'sub_total' => 100000 * $i,
                'total' => 100000 * $i,
                'due_amount' => 100000 * $i,
                'status' => 'DRAFT',
                'creator_id' => $creator->id,
            ]);
            if (! $invoice->unique_hash) {
                $invoice->unique_hash = Hashids::connection(Invoice::class)->encode($invoice->id);
                $invoice->save();
            }

            $note = Note::firstOrCreate([
                'name' => "Confidential Note {$prefix} {$i}",
                'company_id' => $company->id
            ], [
                'type' => 'Invoice',
                'notes' => "Secret Internal Ledger {$prefix} {$i}",
            ]);

            $estimate = Estimate::firstOrCreate([
                'estimate_number' => "EST-{$prefix}-00{$i}",
                'company_id' => $company->id
            ], [
                'customer_id' => $customer->id,
                'estimate_date' => now(),
                'expiry_date' => now()->addDays(15),
                'sub_total' => 50000 * $i,
                'total' => 50000 * $i,
                'status' => 'DRAFT',
                'creator_id' => $creator->id
            ]);
            if (! $estimate->unique_hash) {
                $estimate->unique_hash = Hashids::connection(Estimate::class)->encode($estimate->id);
                $estimate->save();
            }

            $category = ExpenseCategory::firstOrCreate([
                'name' => "Operational {$prefix} {$i}",
                'company_id' => $company->id
            ]);

            $expense = Expense::firstOrCreate([
                'expense_category_id' => $category->id,
                'company_id' => $company->id
            ], [
                'amount' => 25000 * $i,
                'expense_date' => now(),
            ]);

            $paymentMethod = PaymentMethod::where('company_id', $company->id)->first()
                ?? PaymentMethod::create(['name' => "Cash {$prefix}", 'company_id' => $company->id]);

            $payment = Payment::firstOrCreate([
                'payment_number' => "PAY-{$prefix}-00{$i}",
                'company_id' => $company->id
            ], [
                'customer_id' => $customer->id,
                'payment_method_id' => $paymentMethod->id,
                'payment_date' => now(),
                'amount' => 10000 * $i
            ]);
            if (! $payment->unique_hash) {
                $payment->unique_hash = Hashids::connection(Payment::class)->encode($payment->id);
                $payment->save();
            }

            RecurringInvoice::firstOrCreate([
                'customer_id' => $customer->id,
                'company_id' => $company->id,
                'frequency' => 'MONTHLY',
            ], [
                'starts_at' => now(),
                'limit_by' => 'NONE',
                'status' => 'ACTIVE',
                'sub_total' => 100000 * $i,
                'total' => 100000 * $i
            ]);
        }
    }
}
