function show_layer(num) {
	var layers = document.querySelectorAll("svg g.layer");
	
	if (layers.length > 0) {
		layers[num].classList.remove("hidden");
		var li = document.createElement("li");
		var link = document.createElement("a");
		li.appendChild(link);
		
		function show_next(next_num) {
			document.getElementById("link-container").removeChild(li);
			layers[num].classList.add("hidden");
			show_layer(next_num);
		}
		
		var next_num = (num + 1) % layers.length;
		link.onclick = show_next.bind(null, next_num);
		link.href = "#" + next_num;
		link.text = next_num == 0 ? "Restart animation" : "Next step";
		document.getElementById("link-container").appendChild(li);
	}
}

document.addEventListener("DOMContentLoaded", function () {
	var layers = document.querySelectorAll("svg g.layer");
	[].forEach.call(layers, e => e.classList.add("hidden"));
	var layer = parseInt(window.location.hash.substr(1));
	if (layer !== "NaN" && layer < layers.length) {
		show_layer(layer);
	} else {
		show_layer(0);
	}
});

