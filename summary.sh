# File to search
log_file="results.log"

# Extract the numbers using rg and awk (as before)
numbers=$(rg -A 1 "All tests" "$log_file" | awk '/All tests/{getline; for(i=1; i<=NF; i++){if($i ~ /^[0-9]+$/) print $i}}')

# Check if any numbers were found
if [[ -z "$numbers" ]]; then
  echo "No numbers found in the log file."
  exit 1
fi

# Initialize variables
sum=0
count=0
min=
max=

# Loop through the numbers
while IFS= read -r number; do
  ((count++))
  ((sum += number))

  # Initialize min and max on the first iteration
  if [[ -z "$min" ]]; then
    min="$number"
    max="$number"
  else
    if (( number < min )); then
      min="$number"
    fi
    if (( number > max )); then
      max="$number"
    fi
  fi
done <<< "$numbers"

# Calculate the average
if (( count > 0 )); then
  average=$(echo "scale=2; $sum / $count" | bc) # Use bc for decimal precision
else
  average=0
fi

# Output the statistics
echo "Summary Statistics:"
echo "-------------------"
echo "Count:   $count"
echo "Sum:     $sum"
echo "Average: $average"
echo "Min:     $min"
echo "Max:     $max"

exit 0
